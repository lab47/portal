package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lab47/portal"
	"github.com/tmc/go-iroh/relayserver"
	"miren.dev/mflags"
)

func TestMCPHelperProcess(t *testing.T) {
	if os.Getenv("PORTAL_MCP_TEST_PROCESS") != "1" {
		return
	}
	if err := run([]string{"mcp-server"}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestMCPToolRunsRemoteCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	coordinator := httptest.NewServer(portal.NewCoordinator("test-token"))
	defer coordinator.Close()
	relay := httptest.NewServer(relayserver.New())
	defer relay.Close()

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	key := filepath.Join(dir, "operator")
	cert := filepath.Join(dir, "operator-cert.pub")
	for _, path := range []string{ca, key} {
		if err := generateKey(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := issueCertificate(ca, key+".pub", "admin", "operator", cert, time.Hour); err != nil {
		t.Fatal(err)
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := json.Marshal(map[string]any{"identities": map[string][]string{"operator": {account.Username}}})
	if err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyFile, policy, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- (portal.Server{
			Name: "node-a", CoordinatorURL: coordinator.URL, Token: "test-token", CAFile: ca + ".pub",
			Principal: "admin", PolicyFile: policyFile, RelayURL: relay.URL, Listen: "127.0.0.1:0",
		}).Serve(ctx)
	}()
	for {
		res, err := coordinator.Client().Get(coordinator.URL + "/servers/node-a")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode == 200 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("server stopped before check-in: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}

	callParams, err := json.Marshal(mflags.ToolCallRequest{Name: "client", Arguments: map[string]any{
		"name": "node-a", "coordinator": coordinator.URL, "key": key, "cert": cert, "ca": ca + ".pub", "user": account.Username,
		"network-debug": true,
		"arguments":     []string{"--", "/bin/echo", "--mcp-arg"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	capabilityParams, err := json.Marshal(mflags.ToolCallRequest{Name: "capabilities", Arguments: map[string]any{
		"name": "node-a", "coordinator": coordinator.URL, "key": key, "cert": cert, "ca": ca + ".pub",
	}})
	if err != nil {
		t.Fatal(err)
	}
	queryParams, err := json.Marshal(mflags.ToolCallRequest{Name: "query", Arguments: map[string]any{
		"name": "node-a", "coordinator": coordinator.URL, "key": key, "cert": cert, "ca": ca + ".pub",
		"query": fmt.Sprintf("process where pid = %d | .processes[0].pid", os.Getpid()),
	}})
	if err != nil {
		t.Fatal(err)
	}
	aggregateParams, err := json.Marshal(mflags.ToolCallRequest{Name: "query", Arguments: map[string]any{
		"name": "node-a", "coordinator": coordinator.URL, "key": key, "cert": cert, "ca": ca + ".pub",
		"query": fmt.Sprintf("process where pid = %d count, max(rss_bytes) over 300ms every 100ms by pid", os.Getpid()),
	}})
	if err != nil {
		t.Fatal(err)
	}
	client := portal.Client{Name: "node-a", CoordinatorURL: coordinator.URL, KeyFile: key, CertFile: cert, CAFile: ca + ".pub"}
	monitorID, err := client.CreateMonitor(ctx, portal.MonitorRequest{Source: "process", Process: &portal.ProcessFilter{Name: "sleep", Action: "start"}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sleeper := exec.CommandContext(ctx, "/bin/sleep", "20")
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { sleeper.Process.Kill(); sleeper.Wait() }()
	time.Sleep(1200 * time.Millisecond) // Allow the lifecycle poll to buffer the start.
	readParams, err := json.Marshal(mflags.ToolCallRequest{Name: "monitor-read", Arguments: map[string]any{
		"name": "node-a", "coordinator": coordinator.URL, "key": key, "cert": cert, "ca": ca + ".pub",
		"id": monitorID, "duration": "200ms",
	}})
	if err != nil {
		t.Fatal(err)
	}
	deleteParams, err := json.Marshal(mflags.ToolCallRequest{Name: "monitor-delete", Arguments: map[string]any{
		"name": "node-a", "coordinator": coordinator.URL, "key": key, "cert": cert, "ca": ca + ".pub", "id": monitorID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var requests strings.Builder
	encoder := json.NewEncoder(&requests)
	for _, req := range []mflags.MCPRequest{
		{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}`)},
		{JSONRPC: "2.0", ID: 2, Method: "tools/list"},
		{JSONRPC: "2.0", ID: 3, Method: "tools/call", Params: callParams},
		{JSONRPC: "2.0", ID: 4, Method: "tools/call", Params: capabilityParams},
		{JSONRPC: "2.0", ID: 5, Method: "tools/call", Params: queryParams},
		{JSONRPC: "2.0", ID: 6, Method: "tools/call", Params: readParams},
		{JSONRPC: "2.0", ID: 7, Method: "tools/call", Params: deleteParams},
		{JSONRPC: "2.0", ID: 8, Method: "tools/call", Params: json.RawMessage(`{"name":"monitor-read","arguments":{"duration":"0s"}}`)},
		{JSONRPC: "2.0", ID: 9, Method: "tools/call", Params: json.RawMessage(`{"name":"monitor-read","arguments":{"duration":"61s"}}`)},
		{JSONRPC: "2.0", ID: 10, Method: "tools/call", Params: aggregateParams},
	} {
		if err := encoder.Encode(req); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMCPHelperProcess$")
	cmd.Env = append(os.Environ(), "PORTAL_MCP_TEST_PROCESS=1")
	cmd.Stdin = strings.NewReader(requests.String())
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("MCP process: %v, output: %s", err, out)
	}
	if !strings.Contains(diagnostics.String(), "iroh selected path:") || !strings.Contains(diagnostics.String(), "iroh network report:") || bytes.Contains(out, []byte("iroh selected path:")) {
		t.Fatalf("network diagnostics missing or leaked to MCP stdout: stderr=%s stdout=%s", &diagnostics, out)
	}
	decoder := json.NewDecoder(strings.NewReader(string(out)))
	var response struct {
		ID     int              `json:"id"`
		Result json.RawMessage  `json:"result"`
		Error  *mflags.MCPError `json:"error"`
	}
	for id := 1; id <= 10; id++ {
		if err := decoder.Decode(&response); err != nil || response.ID != id || response.Error != nil {
			t.Fatalf("MCP response %d: %+v, %v; output: %s", id, response, err, out)
		}
		switch id {
		case 1:
			var result mflags.InitializeResult
			if err := json.Unmarshal(response.Result, &result); err != nil || result.ProtocolVersion != "2025-06-18" {
				t.Fatalf("MCP negotiated version: %+v, %v", result, err)
			}
		case 2:
			var listed mflags.ToolsListResult
			if err := json.Unmarshal(response.Result, &listed); err != nil || len(listed.Tools) != 6 {
				t.Fatalf("MCP tools: %+v, %v", listed, err)
			}
			want := map[string]bool{"client": true, "capabilities": true, "query": true, "monitor-register": true, "monitor-read": true, "monitor-delete": true}
			for _, tool := range listed.Tools {
				if !want[tool.Name] || tool.InputSchema.Properties["config"].Type != "string" {
					t.Fatalf("unexpected MCP tool or missing config: %+v", tool)
				}
				delete(want, tool.Name)
				if tool.Name == "monitor-read" && tool.InputSchema.Properties["duration"].Default != "5s" {
					t.Fatalf("unbounded MCP monitor read: %+v", tool)
				}
			}
		case 3:
			var result mflags.ToolCallResult
			if err := json.Unmarshal(response.Result, &result); err != nil || result.IsError || len(result.Content) != 1 || result.Content[0].Text != "--mcp-arg\n" {
				t.Fatalf("MCP remote result: %+v, %v", result, err)
			}
		case 4, 5:
			var result mflags.ToolCallResult
			if err := json.Unmarshal(response.Result, &result); err != nil || result.IsError || len(result.Content) != 1 {
				t.Fatalf("MCP query/capabilities result: %+v, %v", result, err)
			}
			if id == 4 {
				var docs portal.Capabilities
				if err := json.Unmarshal([]byte(result.Content[0].Text), &docs); err != nil || len(docs.Sources) == 0 || len(docs.Aggregates) == 0 {
					t.Fatalf("MCP capabilities: %+v, %v", docs, err)
				}
			} else if result.Content[0].Text != fmt.Sprintf("%d\n", os.Getpid()) {
				t.Fatalf("MCP snapshot/jq: %+v", result)
			}
		case 6:
			var result mflags.ToolCallResult
			if err := json.Unmarshal(response.Result, &result); err != nil || result.IsError || len(result.Content) != 1 {
				t.Fatalf("MCP bounded read: %+v, %v", result, err)
			}
			var record portal.MonitorRecord
			if err := json.NewDecoder(strings.NewReader(result.Content[0].Text)).Decode(&record); err != nil || record.Sequence == 0 || record.Event.Process == nil || record.Event.Process.Action != "start" {
				t.Fatalf("MCP monitor record: %+v, %v", record, err)
			}
		case 7:
			var result mflags.ToolCallResult
			if err := json.Unmarshal(response.Result, &result); err != nil || result.IsError {
				t.Fatalf("MCP monitor delete: %+v, %v", result, err)
			}
		case 8, 9:
			var result mflags.ToolCallResult
			if err := json.Unmarshal(response.Result, &result); err != nil || !result.IsError || len(result.Content) != 1 || !strings.Contains(result.Content[0].Text, "invalid read duration") {
				t.Fatalf("MCP accepted unbounded read: %+v, %v", result, err)
			}
		case 10:
			var result mflags.ToolCallResult
			if err := json.Unmarshal(response.Result, &result); err != nil || result.IsError || len(result.Content) != 1 {
				t.Fatalf("MCP aggregate: %+v, %v", result, err)
			}
			var snapshot portal.Snapshot
			text := result.Content[0].Text
			if err := json.Unmarshal([]byte(text), &snapshot); err != nil || snapshot.Aggregation == nil {
				t.Fatalf("MCP aggregate wire: %s, %v", text, err)
			}
			a := snapshot.Aggregation
			if len(a.Columns) != 2 || len(a.Rows) != 1 || len(a.Rows[0].Values) != 2 || string(a.Rows[0].Group["pid"]) != fmt.Sprint(os.Getpid()) || a.Rows[0].Values[0][0] == '0' || strings.Contains(text, `"metrics"`) {
				t.Fatalf("MCP did not compact shared metrics: %s", text)
			}
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
