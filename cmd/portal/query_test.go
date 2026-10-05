package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lab47/portal"
)

func TestClientQueryPipes(t *testing.T) {
	for _, tc := range []struct{ text, name string }{
		{`process where name = "worker|test" | .source`, "worker|test"},
		{`process where name = 'worker\'|test' | .source`, "worker'|test"},
		{`process where name = "worker\"|test" | .source`, `worker"|test`},
		{`process where name = "worker\\"| .source`, `worker\`},
	} {
		r, code, err := parseClientQuery(tc.text)
		if err != nil || code == nil || r.Process == nil || r.Process.Name != tc.name {
			t.Fatalf("quoted pipe %s: %+v, %v", tc.text, r, err)
		}
	}
	r, code, err := parseClientQuery(`memory|.memory.used | . + 1`)
	if err != nil || code == nil || r.Source != "memory" || r.Aggregation != nil {
		t.Fatalf("server selection mixed with jq: %+v, %v", r, err)
	}
	for _, text := range []string{"memory |", "memory |   ", "memory | [", "memory | unknown_function", "bogus | ."} {
		if _, _, err := parseClientQuery(text); err == nil {
			t.Fatalf("invalid client query accepted: %q", text)
		}
	}
	connection := []string{"--name", "node-a", "--coordinator", "http://localhost:8080", "--key", "/missing-key"}
	for _, text := range []string{"memory | .memory.used", "process avg(cpu_percent) over 5s every 1s by pid,name | .aggregation.values | sort_by(.value)"} {
		if err := run(append([]string{"query", "--query", text}, connection...)); err == nil || !strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("pipeline did not reach client request: %v", err)
		}
	}
	if err := run(append([]string{"query", "--query", "memory | ["}, connection...)); err == nil || !strings.Contains(err.Error(), "parse jq") {
		t.Fatalf("invalid jq was not rejected before connecting: %v", err)
	}
}

func TestClientProbeQueryPipe(t *testing.T) {
	r, code, err := parseClientQuery(`disk:completion { let device = device_name; @writes[device] = {calls: count(), sectors: sum(sectors)} } every 1s { emit @writes; clear @writes } after 3s { stop } | [.windows[].table]`)
	if err != nil || code == nil || r.Aggregation == nil || r.Aggregation.Table != "writes" || r.Aggregation.GroupAliases["device_name"] != "device" {
		t.Fatalf("action query pipeline: %+v, %v", r, err)
	}
	var out bytes.Buffer
	snapshot := portal.Snapshot{Source: "disk", Windows: []*portal.AggregationResult{{Table: "writes"}, {Table: "writes"}}}
	if err := writeQueryResult(context.Background(), &out, snapshot, code); err != nil || out.String() != "[\"writes\",\"writes\"]\n" {
		t.Fatalf("action pipeline result: %q, %v", out.String(), err)
	}
}

func TestQueryResultJQ(t *testing.T) {
	snapshot := portal.Snapshot{Source: "memory", Memory: &portal.MemoryInfo{Used: ^uint64(0)}, Processes: []portal.ProcessInfo{{Name: "alpha"}, {Name: "beta"}}}
	for _, tc := range []struct{ filter, want string }{
		{`.memory.used`, "18446744073709551615\n"},
		{`.memory.used + 1`, "18446744073709551616\n"},
		{`.processes[].name | ascii_upcase`, "\"ALPHA\"\n\"BETA\"\n"},
		{`empty`, ""}, {`.missing`, "null\n"}, {`halt`, ""},
	} {
		_, code, err := parseClientQuery("memory | " + tc.filter)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := writeQueryResult(context.Background(), &out, snapshot, code); err != nil || out.String() != tc.want {
			t.Fatalf("%s: %q, %v; want %q", tc.filter, out.String(), err, tc.want)
		}
	}
	_, code, err := parseClientQuery("memory")
	if err != nil || code != nil {
		t.Fatal("plain query acquired a jq stage")
	}
	var out bytes.Buffer
	expected, _ := json.Marshal(snapshot)
	if err := writeQueryResult(context.Background(), &out, snapshot, nil); err != nil || out.String() != string(expected)+"\n" {
		t.Fatalf("plain JSON output changed: %q, %v", out.String(), err)
	}
	_, code, _ = parseClientQuery(`memory | .memory.used[]`)
	if err := writeQueryResult(context.Background(), &out, snapshot, code); err == nil || !strings.Contains(err.Error(), "evaluate jq") {
		t.Fatalf("jq runtime error hidden: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, code, _ = parseClientQuery(`memory | repeat(.)`)
	if err := writeQueryResult(ctx, &out, snapshot, code); !errors.Is(err, context.Canceled) {
		t.Fatalf("jq did not honor cancellation: %v", err)
	}
}

func TestQueryResultTopProcesses(t *testing.T) {
	snapshot := portal.Snapshot{Source: "process", Aggregation: &portal.AggregationResult{Function: "avg", Values: []portal.AggregateValue{
		{Group: map[string]json.RawMessage{"pid": json.RawMessage("1")}, Value: json.RawMessage("2.5")},
		{Group: map[string]json.RawMessage{"pid": json.RawMessage("2")}, Value: json.RawMessage("175")},
		{Group: map[string]json.RawMessage{"pid": json.RawMessage("3")}, Value: json.RawMessage("10")},
	}}}
	_, code, err := parseClientQuery(`process avg(cpu_percent) over 5s every 1s by pid,name | [.aggregation.values | sort_by(.value) | reverse | .[:2][] | {pid:.group.pid, cpu:.value}]`)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeQueryResult(context.Background(), &out, snapshot, code); err != nil || out.String() != "[{\"cpu\":175,\"pid\":2},{\"cpu\":10,\"pid\":3}]\n" {
		t.Fatalf("top process ordering/projection: %s, %v", out.String(), err)
	}
}

func TestQueryResultMultipleMetrics(t *testing.T) {
	snapshot := portal.Snapshot{Source: "disk", Aggregation: &portal.AggregationResult{Metrics: []*portal.AggregationResult{
		{Function: "count", Counts: []portal.AggregateCount{{Group: map[string]json.RawMessage{"pid": json.RawMessage("42")}, Count: 3}}},
		{Function: "sum", Field: "sectors", Values: []portal.AggregateValue{{Group: map[string]json.RawMessage{"pid": json.RawMessage("42")}, Value: json.RawMessage("18446744073709551615")}}},
	}}}
	request, code, err := parseClientQuery(`disk count, sum(sectors) over 30s by pid | .aggregation.metrics[] | select(.function == "sum") | .values[0].value`)
	if err != nil || len(request.Aggregation.Metrics) != 2 {
		t.Fatalf("multi-metric pipeline: %+v, %v", request, err)
	}
	var out bytes.Buffer
	if err := writeQueryResult(context.Background(), &out, snapshot, code); err != nil || out.String() != "18446744073709551615\n" {
		t.Fatalf("multi-metric selection or precision: %s, %v", out.String(), err)
	}
}

func TestQueryResultNamedTableMetrics(t *testing.T) {
	_, code, err := parseClientQuery(`syscalls:completion { @io[proc: pid] = {total: sum(duration_ns), ops: count()} } every 1s { emit @io; clear @io } after 2s { stop } | .windows[].rows[] | {proc: .group.proc, ops: .values.ops, total: .values.total}`)
	if err != nil {
		t.Fatal(err)
	}
	columns := []portal.AggregateMetric{{Name: "total", Function: "sum", Field: "duration_ns"}, {Name: "ops", Function: "count"}}
	snapshot := portal.Snapshot{Source: "syscalls", Windows: []*portal.AggregationResult{
		{Table: "io", Columns: columns, Rows: []portal.AggregateRow{{Group: map[string]json.RawMessage{"proc": json.RawMessage("7")}, Values: []json.RawMessage{json.RawMessage("18446744073709551616"), json.RawMessage("2")}}}},
		{Table: "io", Columns: columns, Rows: []portal.AggregateRow{}},
	}}
	// Exercise the server -> Go client -> jq path, not only local encoding.
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var received portal.Snapshot
	if err := json.Unmarshal(data, &received); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeQueryResult(context.Background(), &out, received, code); err != nil || out.String() != "{\"ops\":2,\"proc\":7,\"total\":18446744073709551616}\n" {
		t.Fatalf("named metric pipeline: %q, %v", out.String(), err)
	}
}

func TestQueryResultMultipleSources(t *testing.T) {
	r, code, err := parseClientQuery(`syscalls { @calls[] = count() } process { @starts[] = count() } after 1s { emit @calls; emit @starts } | .tables[] | {source, table: .aggregation.table, ops: .aggregation.rows[0].values.value}`)
	if err != nil || len(r.Probes) != 2 {
		t.Fatalf("multi-source pipeline: %+v, %v", r, err)
	}
	snapshot := portal.Snapshot{Source: "script", Tables: []portal.Snapshot{
		{Source: "syscalls", Aggregation: &portal.AggregationResult{Table: "calls", Columns: []portal.AggregateMetric{{Name: "value", Function: "count"}}, Rows: []portal.AggregateRow{{Group: map[string]json.RawMessage{}, Values: []json.RawMessage{json.RawMessage("19")}}}}},
		{Source: "process", Aggregation: &portal.AggregationResult{Table: "starts", Columns: []portal.AggregateMetric{{Name: "value", Function: "count"}}, Rows: []portal.AggregateRow{{Group: map[string]json.RawMessage{}, Values: []json.RawMessage{json.RawMessage("7")}}}}},
	}}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var received portal.Snapshot
	if err := json.Unmarshal(data, &received); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeQueryResult(context.Background(), &out, received, code); err != nil || out.String() != "{\"ops\":19,\"source\":\"syscalls\",\"table\":\"calls\"}\n{\"ops\":7,\"source\":\"process\",\"table\":\"starts\"}\n" {
		t.Fatalf("nested table pipeline: %q, %v", out.String(), err)
	}
}
