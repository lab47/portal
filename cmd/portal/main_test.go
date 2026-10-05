package main

import (
	"strings"
	"testing"
)

func TestClientCommandSeparator(t *testing.T) {
	args := []string{"client", "--name", "node-a", "--coordinator", "http://localhost:8080", "--key", "/missing-key", "--ca", "/missing-ca", "--cert", "/missing-cert", "--user", "deploy"}
	withSeparator := append(append([]string{}, args...), "--", "/bin/echo", "--flag")
	if err := run(withSeparator); err == nil || !strings.Contains(err.Error(), "/missing-key") {
		t.Fatalf("command arguments after -- were not passed through: %v", err)
	}
	withoutSeparator := append(append([]string{}, args...), "/bin/echo", "--flag")
	if err := run(withoutSeparator); err == nil || !strings.Contains(err.Error(), "unknown flag: --flag") {
		t.Fatalf("unknown CLI flag was not rejected: %v", err)
	}
}

func TestCapabilitiesCommand(t *testing.T) {
	connection := []string{"--name", "node-a", "--coordinator", "http://localhost:8080", "--key", "/missing-key"}
	for _, command := range [][]string{{"capabilities"}, {"query", "--query", "capabilities"}} {
		if err := run(append(command, connection...)); err == nil || !strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("capability command did not use client credentials: %v", err)
		}
	}
}

func TestServerRequiresPolicy(t *testing.T) {
	args := []string{"server", "--name", "node-a", "--coordinator", "http://localhost:8080", "--token", "test", "--ca", "/missing-ca"}
	if err := run(args); err == nil || !strings.Contains(err.Error(), "policy file") {
		t.Fatalf("server accepted missing policy: %v", err)
	}
	if err := run(append(args, "--policy", "/missing-policy")); err == nil || !strings.Contains(err.Error(), "/missing-policy") {
		t.Fatalf("server ignored policy flag: %v", err)
	}
}

func TestServerLabels(t *testing.T) {
	args := []string{"server", "--name", "node-a", "--coordinator", "http://localhost:8080", "--token", "test", "--ca", "/missing-ca", "--policy", "/missing-policy"}
	valid := append(append([]string{}, args...), "--label", "role=worker", "--label", "region=eu,west=2")
	if err := run(valid); err == nil || !strings.Contains(err.Error(), "/missing-policy") {
		t.Fatalf("labels with commas and equals were not accepted: %v", err)
	}
	for _, tc := range [][]string{
		{"--label", "no-equals"},
		{"--label", "=no-key"},
		{"--label", "role=worker", "--label", "role=database"},
	} {
		if err := run(append(append([]string{}, args...), tc...)); err == nil || !strings.Contains(err.Error(), "label") {
			t.Fatalf("invalid labels %v accepted: %v", tc, err)
		}
	}
}

func TestMonitorPacketFlags(t *testing.T) {
	base := []string{"monitor", "--name", "node-a", "--coordinator", "http://localhost:8080", "--key", "/missing-key"}
	valid := append(append([]string{}, base...), "--source", "packets", "--protocol", "tcp", "--direction", "outgoing", "--dst-port", "80")
	if err := run(valid); err == nil || !strings.Contains(err.Error(), "/missing-key") {
		t.Fatalf("packet monitor flags not accepted: %v", err)
	}
	for _, flags := range [][]string{
		{"--source", "packets", "--protocol", "tcp", "--dst-port", "65536"},
		{"--source", "syscalls", "--protocol", "tcp"},
		{"--source", "packets", "--dst-port", "80"},
	} {
		if err := run(append(append([]string{}, base...), flags...)); err == nil || strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("invalid monitor flags %v passed validation: %v", flags, err)
		}
	}
}

func TestMonitorQueryFlag(t *testing.T) {
	base := []string{"monitor", "--name", "node-a", "--coordinator", "http://localhost:8080", "--key", "/missing-key"}
	valid := append(append([]string{}, base...), "--query", "packets where protocol = tcp and direction = outgoing and dst.port = 80")
	if err := run(valid); err == nil || !strings.Contains(err.Error(), "/missing-key") {
		t.Fatalf("query was not accepted: %v", err)
	}
	for _, args := range [][]string{
		{"--query", "packets where protocol = tcp and dst.port = 80", "--dst-port", "443"},
		{"--query", "packets where protocol = tcp and dst.port = 80", "--source", "packets"},
		{"--query", "packets", "--source", "syscalls"},
		{"--query", "packets", "--pid", "0"},
		{"--query", "packets where unknown = 80"},
	} {
		if err := run(append(append([]string{}, base...), args...)); err == nil || strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("invalid query flags %v passed validation: %v", args, err)
		}
	}
}

func TestMonitorProcessFlags(t *testing.T) {
	base := []string{"monitor", "--name", "node-a", "--coordinator", "http://localhost:8080", "--key", "/missing-key"}
	for _, flags := range [][]string{
		{"--source", "process", "--process-name", "worker", "--process-action", "start"},
		{"--query", "process where name = worker and action = start"},
	} {
		if err := run(append(append([]string{}, base...), flags...)); err == nil || !strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("valid process flags %v rejected: %v", flags, err)
		}
	}
	for _, flags := range [][]string{
		{"--source", "process", "--process-action", "restart"},
		{"--source", "process", "--syscall", "1"},
		{"--query", "process", "--process-name", "worker"},
	} {
		if err := run(append(append([]string{}, base...), flags...)); err == nil || strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("invalid process flags %v accepted: %v", flags, err)
		}
	}
}

func TestMonitorDiskFlags(t *testing.T) {
	base := []string{"monitor", "--name", "node-a", "--coordinator", "http://localhost:8080", "--key", "/missing-key"}
	for _, flags := range [][]string{
		{"--source", "disk", "--device", "0x800", "--operation", "write"},
		{"--query", "disk where operation = read"},
		{"--source", "process", "--process-name", "worker*"},
	} {
		if err := run(append(append([]string{}, base...), flags...)); err == nil || !strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("valid monitor flags %v rejected: %v", flags, err)
		}
	}
	for _, flags := range [][]string{
		{"--source", "disk", "--device", "0"},
		{"--source", "disk", "--operation", "trim"},
		{"--source", "syscalls", "--operation", "read"},
		{"--source", "process", "--process-name", "wo*rker"},
		{"--query", "disk", "--device", "0x800"},
	} {
		if err := run(append(append([]string{}, base...), flags...)); err == nil || strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("invalid monitor flags %v accepted: %v", flags, err)
		}
	}
}

func TestQuerySnapshotFlags(t *testing.T) {
	base := []string{"query", "--name", "node-a", "--coordinator", "http://localhost:8080", "--key", "/missing-key"}
	for _, query := range []string{"process", "process where pid = 42 and name = worker*", "cpu", "memory", "network where name = eth*", "kernel", "sensors", "containers", "gpu where name = '*A100'", "syscalls where syscall = 2 count over 30s by pid", "process where action = start count over 1m by name", "packets sum(length) over 30s by dst.ip", "disk avg(sectors) over 30s", "process count_distinct(name) over 1m", "packets percentile(length,95) over 30s"} {
		if err := run(append(append([]string{}, base...), "--query", query)); err == nil || !strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("snapshot query %q rejected before connecting: %v", query, err)
		}
	}
	for _, query := range []string{"", "process where action = start", "packets where protocol = tcp", "disk", "syscalls", "network where pid = 2", "cpu where name = cpu0"} {
		if err := run(append(append([]string{}, base...), "--query", query)); err == nil || strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("unsupported snapshot query %q accepted: %v", query, err)
		}
	}
}

func TestRegisteredMonitorFlags(t *testing.T) {
	connection := []string{"--name", "node-a", "--coordinator", "http://localhost:8080", "--key", "/missing-key"}
	for _, args := range [][]string{
		{"monitor-register", "--query", "process where name = worker*"},
		{"monitor-register", "--query", "process", "--ttl", "30m"},
		{"monitor-read", "--id", strings.Repeat("a", 32), "--after", "17"},
		{"monitor-read", "--id", strings.Repeat("a", 32), "--after-timestamp", "@40000000586846a500000000"},
		{"monitor-delete", "--id", strings.Repeat("a", 32)},
	} {
		if err := run(append(args, connection...)); err == nil || !strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("registered monitor flags rejected: %v", err)
		}
	}
	for _, args := range [][]string{
		{"monitor-register"},
		{"monitor-register", "--query", "memory"},
		{"monitor-register", "--query", "process", "--ttl", "-1s"},
		{"monitor-register", "--query", "process", "--ttl", "invalid"},
		{"monitor-read", "--id", strings.Repeat("a", 32), "--after", "-1"},
		{"monitor-read", "--id", "bad"},
		{"monitor-read", "--id", strings.Repeat("a", 32), "--after-timestamp", "bad"},
		{"monitor-read", "--id", strings.Repeat("a", 32), "--after-timestamp", "@40000000586846a500000000", "--after", "0"},
		{"monitor-delete"},
	} {
		if err := run(append(args, connection...)); err == nil || strings.Contains(err.Error(), "/missing-key") {
			t.Fatalf("invalid registered monitor flags accepted: %v", err)
		}
	}
}
