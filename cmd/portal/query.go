package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
