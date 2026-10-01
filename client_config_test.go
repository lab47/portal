package portal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientConfigDefaultsAndOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	if _, err := LoadClientConfig(""); err != nil {
		t.Fatalf("missing default config prevented flag-only usage: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"key":"operator","ca":"ca.pub","coordinator":"https://inventory.example","principal":"operators"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := (Client{ConfigFile: path, Name: "node", CoordinatorURL: "https://override.example"}).configured()
	if err != nil || c.KeyFile != filepath.Join(dir, "operator") || c.CertFile != filepath.Join(dir, "operator-cert.pub") || c.CAFile != filepath.Join(dir, "ca.pub") || c.Principal != "operators" || c.CoordinatorURL != "https://override.example" || c.Name != "node" {
		t.Fatalf("config resolution: %+v, %v", c, err)
	}
	c, err = (Client{ConfigFile: path, KeyFile: "/explicit/key", CertFile: "/explicit/cert", CAFile: "/explicit/ca", Principal: "admin"}).configured()
	if err != nil || c.KeyFile != "/explicit/key" || c.CertFile != "/explicit/cert" || c.CAFile != "/explicit/ca" || c.Principal != "admin" {
		t.Fatalf("explicit credentials not preserved: %+v, %v", c, err)
	}
	if _, err := LoadClientConfig(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing explicit config silently ignored")
	}
	for _, data := range []string{`{"unknown":true}`, `{} {}`, strings.Repeat(" ", 65537), `{broken`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadClientConfig(path); err == nil {
			t.Fatalf("invalid config accepted: %.30s", data)
		}
	}
}
