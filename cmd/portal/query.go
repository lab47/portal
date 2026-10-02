package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"sort"
	"strings"

	"github.com/itchyny/gojq"
	"github.com/lab47/portal"
)

// Only the first unquoted pipe separates the server DSL from local jq.
// Subsequent pipes belong to jq; quoted pipes remain part of server values.
func parseClientQuery(text string) (portal.MonitorRequest, *gojq.Code, error) {
	selection, filter := text, ""
	piped := false
	var quote rune
	escaped := false
	for i, ch := range text {
		if quote != 0 {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
		} else if ch == '|' {
			selection, filter, piped = text[:i], strings.TrimSpace(text[i+1:]), true
			break
		}
	}
	request, err := portal.ParseMonitorQuery(strings.TrimSpace(selection))
	if err != nil || !piped {
		return request, nil, err
	}
	if filter == "" {
		return request, nil, errors.New("jq expression required after |")
	}
	query, err := gojq.Parse(filter)
	if err != nil {
		return request, nil, fmt.Errorf("parse jq expression: %w", err)
	}
	code, err := gojq.Compile(query)
	if err != nil {
		return request, nil, fmt.Errorf("compile jq expression: %w", err)
	}
	return request, code, nil
}

func writeQueryResult(ctx context.Context, out io.Writer, snapshot portal.Snapshot, code *gojq.Code) error {
	if code == nil {
		return json.NewEncoder(out).Encode(snapshot)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber() // gojq accepts json.Number and preserves large integers.
	var input any
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	iter := code.RunWithContext(ctx, input)
	for {
		value, ok := iter.Next()
		if !ok {
			return nil
		}
		if err, ok := value.(error); ok {
			if halt, ok := err.(*gojq.HaltError); ok && halt.Value() == nil {
				return nil
			}
			return fmt.Errorf("evaluate jq expression: %w", err)
		}
		data, err := gojq.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, string(data)); err != nil {
			return err
		}
	}
}

func validateFoldedQuery(request portal.MonitorRequest, field string, index int) error {
	if request.Mode != "aggregate" || request.Aggregation == nil || (field != "user.stack" && field != "kernel.stack") || !slices.Contains(request.Aggregation.GroupBy, field) {
		return errors.New("folded output requires an aggregate grouped by the selected user.stack or kernel.stack")
	}
	if request.Aggregation.Compact || request.Aggregation.Nonzero || request.Aggregation.Limit != 0 || request.Aggregation.SortMetric != 0 {
		return errors.New("folded output cannot be combined with compact result controls")
	}
	metrics := max(1, len(request.Aggregation.Metrics))
	if index < 0 || index >= metrics {
		return errors.New("folded-metric must select an existing zero-based metric index")
	}
	return nil
}

// Stack keys are leaf-first; flame graph folded paths must be root-first.
// Other group dimensions become prefix frames, retaining process/device identity.
func writeFoldedResult(out io.Writer, snapshot portal.Snapshot, field string, index int) error {
	a := snapshot.Aggregation
	if a == nil {
		return errors.New("folded output requires an aggregation result")
	}
	if len(a.Metrics) != 0 {
		if index < 0 || index >= len(a.Metrics) {
			return errors.New("folded metric missing from result")
		}
		a = a.Metrics[index]
	} else if index != 0 {
		return errors.New("folded metric missing from result")
	}
	if a == nil || !slices.Contains(a.GroupBy, field) {
		return errors.New("folded stack grouping missing from result")
	}
	weights := make(map[string]*big.Rat)
	escape := strings.NewReplacer("%", "%25", ";", "%3B", "\n", "%0A", "\r", "%0D", "\t", "%09")
	controls := strings.NewReplacer("\n", "%0A", "\r", "%0D", "\t", "%09")
	add := func(group map[string]json.RawMessage, value json.RawMessage) error {
		var stack string
		if bytes.Equal(bytes.TrimSpace(group[field]), []byte("null")) {
			return errors.New("folded stack is not a string")
		}
		if err := json.Unmarshal(group[field], &stack); err != nil {
			return fmt.Errorf("folded stack is not a string: %w", err)
		}
		if !json.Valid(value) {
			return errors.New("invalid folded weight")
		}
		weight, ok := new(big.Rat).SetString(string(value))
		if !ok || weight.Sign() < 0 {
			return errors.New("folded weights must be nonnegative numbers; null/negative metrics cannot be exported")
		}
		path := make([]string, 0, len(group))
		for _, name := range a.GroupBy {
			if name == field {
				continue
			}
			v, ok := group[name]
			if !ok || !json.Valid(v) {
				return fmt.Errorf("folded group missing %s", name)
			}
			path = append(path, escape.Replace(name+"="+string(v)))
		}
		frames := strings.Split(stack, ";")
		if stack == "" {
			frames = []string{"[empty stack]"}
		}
		slices.Reverse(frames)
		for _, frame := range frames {
			// Existing stack keys already escape semicolons/percent; retain that
			// encoding and sanitize controls for older server results as well.
			frame = controls.Replace(frame)
			path = append(path, frame)
		}
		key := strings.Join(path, ";")
		if weights[key] == nil {
			weights[key] = new(big.Rat)
		}
		weights[key].Add(weights[key], weight)
		return nil
	}
	if a.Function == "" || a.Function == "count" {
		for _, row := range a.Counts {
			if err := add(row.Group, json.RawMessage(fmt.Sprint(row.Count))); err != nil {
				return err
			}
		}
	} else {
		for _, row := range a.Values {
			if err := add(row.Group, row.Value); err != nil {
				return err
			}
		}
	}
	keys := make([]string, 0, len(weights))
	for key := range weights {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var output strings.Builder
	for _, key := range keys {
		weight := weights[key]
		value := weight.FloatString(18)
		if weight.IsInt() {
			value = weight.Num().String()
		}
		fmt.Fprintf(&output, "%s %s\n", key, value)
	}
	_, err := io.WriteString(out, output.String())
	return err
}
