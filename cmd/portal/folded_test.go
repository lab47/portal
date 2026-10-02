package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lab47/portal"
)

func TestFoldedStacksAndPrecision(t *testing.T) {
	group := func(pid, path string) map[string]json.RawMessage {
		stack, _ := json.Marshal(path)
		return map[string]json.RawMessage{"pid": json.RawMessage(pid), "user.stack": stack}
	}
	a := &portal.AggregationResult{Function: "count", GroupBy: []string{"user.stack", "pid"}, Counts: []portal.AggregateCount{
		{Group: group("42", "leaf;middle;root"), Count: 3},
		{Group: group("7", "leaf;root"), Count: 2},
		{Group: group("42", "leaf;middle;root"), Count: 5},
	}}
	var out bytes.Buffer
	if err := writeFoldedResult(&out, portal.Snapshot{Aggregation: a}, "user.stack", 0); err != nil || out.String() != "pid=42;root;middle;leaf 8\npid=7;root;leaf 2\n" {
		t.Fatalf("order/grouping/merging: %q, %v", out.String(), err)
	}
	a = &portal.AggregationResult{Function: "sum", Field: "duration_ns", GroupBy: []string{"user.stack"}, Values: []portal.AggregateValue{{Group: group("42", "leaf;root"), Value: json.RawMessage("18446744073709551615")}}}
	metrics := portal.Snapshot{Aggregation: &portal.AggregationResult{Metrics: []*portal.AggregationResult{
		{Function: "count", GroupBy: []string{"user.stack"}, Counts: []portal.AggregateCount{{Group: group("42", "leaf;root"), Count: 2}}}, a,
	}}}
	out.Reset()
	if err := writeFoldedResult(&out, metrics, "user.stack", 1); err != nil || out.String() != "root;leaf 18446744073709551615\n" {
		t.Fatalf("metric/precision: %q, %v", out.String(), err)
	}
	a.Values[0].Value = json.RawMessage("0.125")
	out.Reset()
	if err := writeFoldedResult(&out, metrics, "user.stack", 1); err != nil || out.String() != "root;leaf 0.125000000000000000\n" {
		t.Fatalf("decimal folded weight: %q, %v", out.String(), err)
	}
	for _, value := range []string{"null", "-3", `"7"`, "1/2"} {
		a.Values = append(a.Values[:1], portal.AggregateValue{Group: group("42", "other;root"), Value: json.RawMessage(value)})
		out.Reset()
		if err := writeFoldedResult(&out, metrics, "user.stack", 1); err == nil || out.Len() != 0 {
			t.Fatalf("invalid weight gave partial output: %s: %q, %v", value, out.String(), err)
		}
	}
}

func TestFoldedEscapingAndEmptyOutput(t *testing.T) {
	stack, _ := json.Marshal("leaf%3Bsafe;[failed\n-17]")
	name, _ := json.Marshal("a;b%\n")
	a := &portal.AggregationResult{GroupBy: []string{"name", "kernel.stack"}, Counts: []portal.AggregateCount{{Group: map[string]json.RawMessage{"name": name, "kernel.stack": stack}, Count: 1}}}
	var out bytes.Buffer
	if err := writeFoldedResult(&out, portal.Snapshot{Aggregation: a}, "kernel.stack", 0); err != nil || out.String() != "name=\"a%3Bb%25\\n\";[failed%0A-17];leaf%3Bsafe 1\n" {
		t.Fatalf("unsafe folded labels: %q, %v", out.String(), err)
	}
	a.Counts = nil
	out.Reset()
	if err := writeFoldedResult(&out, portal.Snapshot{Aggregation: a}, "kernel.stack", 0); err != nil || out.Len() != 0 {
		t.Fatalf("empty export: %q, %v", out.String(), err)
	}
	if err := writeFoldedResult(&out, portal.Snapshot{}, "kernel.stack", 0); err == nil {
		t.Fatal("missing aggregation accepted")
	}
}

func TestFoldedOptionsValidateBeforeConnecting(t *testing.T) {
	for _, tc := range []struct {
		query string
		flags []string
		want  string
	}{
		{"process", []string{"--format", "folded"}, "grouped"},
		{"syscalls where stacks = user count over 1s by user.stack", []string{"--format", "invalid"}, "format"},
		{"syscalls where stacks = user count over 1s by user.stack | .", []string{"--format", "folded"}, "jq pipeline"},
		{"syscalls where stacks = user count over 1s by user.stack", []string{"--format", "folded", "--folded-metric", "1"}, "index"},
		{"syscalls where stacks = user count over 1s by user.stack", []string{"--format", "folded", "--folded-stack", "kernel.stack"}, "grouped"},
	} {
		args := append([]string{"query", "--query", tc.query}, tc.flags...)
		if err := run(args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("options %+v: %v", tc, err)
		}
	}
	r, _, err := parseClientQuery("syscalls where stacks = both and user.stack.offsets = false count, sum(pid) over 1s by user.stack")
	if err != nil || validateFoldedQuery(r, "user.stack", 1) != nil {
		t.Fatalf("valid shaped multi query: %v", err)
	}
}
