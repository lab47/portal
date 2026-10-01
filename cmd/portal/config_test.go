package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lab47/portal"
)

func TestConfigInitAndClientCommands(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	path, err := portal.DefaultClientConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"config", "init", "--key", filepath.Join(dir, "missing-key"), "--ca", filepath.Join(dir, "ca.pub"), "--coordinator", "https://inventory.example", "--ca-url", "https://ca.example"}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	config, err := portal.LoadClientConfig(path)
	if err != nil || config.CAURL != "https://ca.example" || config.Coordinator != "https://inventory.example" || config.CA != filepath.Join(dir, "ca.pub") {
		t.Fatalf("saved config: %+v, %v", config, err)
	}
	info, err := os.Stat(path)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatalf("config permissions: %v, %v", info, err)
	}
	if err := run(args); err == nil {
		t.Fatal("config init overwrote existing config")
	}
	for _, args := range [][]string{
		{"client", "--name", "node", "--", "echo"},
		{"query", "--name", "node", "--query", "memory"},
		{"monitor", "--name", "node", "--query", "process"},
		{"monitor-register", "--name", "node", "--query", "process"},
		{"monitor-read", "--name", "node", "--id", strings.Repeat("a", 32)},
		{"monitor-delete", "--name", "node", "--id", strings.Repeat("a", 32)},
	} {
		if err := run(args); err == nil || !strings.Contains(err.Error(), "missing-key") {
			t.Fatalf("command did not use default config: %v: %v", args, err)
		}
	}
	if err := run([]string{"query", "--name", "node", "--query", "memory", "--key", filepath.Join(dir, "override-key")}); err == nil || !strings.Contains(err.Error(), "override-key") {
		t.Fatalf("flag did not override config: %v", err)
	}
	if err := run([]string{"cert", "refresh"}); err == nil || !strings.Contains(err.Error(), "missing-key.refresh") {
		t.Fatalf("refresh did not use config: %v", err)
	}
}

func TestClientConfigPreservesCAURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	caURL := "https://ca.example.com/ca.pub"
	if err := run([]string{"config", "init", "--config", path, "--key", "operator", "--ca", caURL, "--coordinator", "https://inventory.example"}); err != nil {
		t.Fatal(err)
	}
	c, err := portal.LoadClientConfig(path)
	if err != nil || c.CA != caURL || !filepath.IsAbs(c.Key) {
		t.Fatalf("CA URL was treated as a file path: %v", err)
	}
}
