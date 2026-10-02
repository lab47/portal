package portal

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSymbolAndStackQueries(t *testing.T) {
	r, err := ParseMonitorQuery("symbols where target = process and pid = 123 and addresses in (0xffffffffffffffff, 42)")
	if err != nil || r.Mode != "snapshot" || r.Symbols.PID != 123 || r.Symbols.Addresses[0] != ^uint64(0) || r.Symbols.Addresses[1] != 42 {
		t.Fatalf("address query: %+v, %v", r, err)
	}
	r, err = ParseMonitorQuery("symbols where target = process and pid = 123 and name = handle* and limit = 17")
	if err != nil || r.Mode != "snapshot" || r.Symbols.PID != 123 || r.Symbols.Name != "handle*" || r.Symbols.Limit != 17 {
		t.Fatalf("process name query: %+v, %v", r, err)
	}
	r, err = ParseMonitorQuery("syscalls where stacks = both count over 1s by pid, user.stack, kernel.stack")
	if err != nil || !r.Stacks.User || !r.Stacks.Kernel || !r.Stacks.Symbolize {
		t.Fatalf("stack query: %+v, %v", r, err)
	}
	for _, query := range []string{
		"process where stacks = user", "syscalls count over 1s by user.stack",
		"syscalls where stacks = kernel count over 1s by user.stack",
		"symbols where target = kernel and addresses in (-1)",
		"symbols where target = kernel and name = vfs_* and addresses in (42)",
		"symbols where target = kernel and name = vfs_* count over 1s",
		"symbols where target = process and name = handle*",
		"symbols where target = process and pid = 123 and name = handle* and addresses in (42)",
	} {
		if _, err := ParseMonitorQuery(query); err == nil {
			t.Fatalf("accepted invalid query: %s", query)
		}
	}
	frames := &CapturedStack{Frames: []SymbolFrame{{Address: "0x123", Name: "run", Module: "app", Offset: 7}, {Address: "0x456", Error: "unresolved"}}}
	event := Event{PID: 123, UserStack: frames}
	if got := eventGroupFields(event, nil)["user.stack"]; got != "app:run+0x7;0x456" {
		t.Fatalf("wrong collapsed stack: %v", got)
	}
	data, err := json.Marshal(event)
	if err != nil || !strings.Contains(string(data), `"user_stack"`) || !strings.Contains(string(data), `"syscall":0`) {
		t.Fatalf("lost syscall stack: %s, %v", data, err)
	}
}

func TestSymbolAndStackProofs(t *testing.T) {
	ca, signer := testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	nonce := []byte(strings.Repeat("s", 32))
	for _, r := range []MonitorRequest{
		{Source: "symbols", Mode: "snapshot", Symbols: &SymbolRequest{Target: "kernel", Addresses: []uint64{42}}},
		{Source: "syscalls", Stacks: &StackCapture{User: true}},
	} {
		proof, err := signMonitor(signer, cert, nonce, r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err != nil {
			t.Fatal(err)
		}
		if r.Symbols != nil {
			proof.Symbols = &SymbolRequest{Target: "kernel", Addresses: []uint64{43}}
		} else {
			proof.Stacks = &StackCapture{Kernel: true}
		}
		if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
			t.Fatal("modified capture/lookup passed signature check")
		}
	}
}
