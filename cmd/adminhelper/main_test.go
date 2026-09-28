package main

import (
	"strings"
	"testing"
)

func TestClientCommandSeparator(t *testing.T) {
	args := []string{"client", "--name", "node-a", "--coordinator", "http://localhost:8080", "--key", "/missing-key", "--cert", "/missing-cert", "--user", "deploy"}
	withSeparator := append(append([]string{}, args...), "--", "/bin/echo", "--flag")
	if err := run(withSeparator); err == nil || !strings.Contains(err.Error(), "/missing-key") {
		t.Fatalf("command arguments after -- were not passed through: %v", err)
	}
	withoutSeparator := append(append([]string{}, args...), "/bin/echo", "--flag")
	if err := run(withoutSeparator); err == nil || !strings.Contains(err.Error(), "unknown flag: --flag") {
		t.Fatalf("unknown CLI flag was not rejected: %v", err)
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
