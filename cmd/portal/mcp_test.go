package main

import (
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
		"name": "node-a", "coordinator": coordinator.URL, "key": key, "cert": cert, "user": account.Username,
		"arguments": []string{"--", "/bin/echo", "--mcp-arg"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var requests strings.Builder
	encoder := json.NewEncoder(&requests)
	for _, req := range []mflags.MCPRequest{
		{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: json.RawMessage(`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}`)},
		{JSONRPC: "2.0", ID: 2, Method: "tools/list"},
		{JSONRPC: "2.0", ID: 3, Method: "tools/call", Params: callParams},
	} {
		if err := encoder.Encode(req); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMCPHelperProcess$")
	cmd.Env = append(os.Environ(), "PORTAL_MCP_TEST_PROCESS=1")
	cmd.Stdin = strings.NewReader(requests.String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("MCP process: %v, output: %s", err, out)
	}
	decoder := json.NewDecoder(strings.NewReader(string(out)))
	var response struct {
		ID     int              `json:"id"`
		Result json.RawMessage  `json:"result"`
		Error  *mflags.MCPError `json:"error"`
	}
	for id := 1; id <= 3; id++ {
		if err := decoder.Decode(&response); err != nil || response.ID != id || response.Error != nil {
			t.Fatalf("MCP response %d: %+v, %v; output: %s", id, response, err, out)
		}
		switch id {
		case 2:
			var listed mflags.ToolsListResult
			if err := json.Unmarshal(response.Result, &listed); err != nil || len(listed.Tools) != 1 || listed.Tools[0].Name != "client" || listed.Tools[0].InputSchema.Properties["arguments"].Type != "array" {
				t.Fatalf("MCP tools: %+v, %v", listed, err)
			}
		case 3:
			var result mflags.ToolCallResult
			if err := json.Unmarshal(response.Result, &result); err != nil || result.IsError || len(result.Content) != 1 || result.Content[0].Text != "--mcp-arg\n" {
				t.Fatalf("MCP remote result: %+v, %v", result, err)
			}
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
