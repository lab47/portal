package portal

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestServerConfigDefaultsAndOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	if _, err := LoadServerConfig(""); err != nil {
		t.Fatal(err)
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	c := ServerConfig{
		Name: "configured-node", Coordinator: "https://inventory.example/register/config-token",
		CA:         string(ssh.MarshalAuthorizedKey(testSigner(t).PublicKey())),
		Identities: map[string][]string{"operator": {account.Username}},
		Principal:  "operators", Relay: "https://relay.example", Listen: "127.0.0.1:9999",
		Labels: map[string]string{"role": "worker", "region": "west"},
	}
	path, err := DefaultServerConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := (Server{}).configured()
	if err != nil || s.Name != c.Name || s.Token != "config-token" || s.CoordinatorURL != "https://inventory.example" || s.CAPublicKey != c.CA || s.Principal != "operators" || s.RelayURL != c.Relay || s.Listen != c.Listen || s.Identities["operator"][0] != account.Username {
		t.Fatalf("defaults not loaded: %v", err)
	}
	s, err = (Server{
		ConfigFile: path, Name: "override", Token: "override-token", CoordinatorURL: "https://override.example",
		CAFile: "override-ca", PolicyFile: "override-policy", Principal: "admin",
		RelayURL: "https://override-relay.example", Listen: "127.0.0.1:8888",
		Labels: map[string]string{"role": "api", "extra": "new"},
	}).configured()
	if err != nil || s.Name != "override" || s.Token != "override-token" || s.CoordinatorURL != "https://override.example" || s.CAPublicKey != "" || s.Identities != nil || s.CAFile != "override-ca" || s.PolicyFile != "override-policy" || s.Principal != "admin" || s.Listen != "127.0.0.1:8888" || s.RelayURL != "https://override-relay.example" {
		t.Fatalf("overrides not honored: %v", err)
	}
	if s.Labels["role"] != "api" || s.Labels["region"] != "west" || s.Labels["extra"] != "new" {
		t.Fatalf("labels not merged: %v", s.Labels)
	}
	if _, err := (Server{CoordinatorURL: "https://other.example"}).configured(); err == nil {
		t.Fatal("saved token would be sent to a different coordinator")
	}
	s, err = (Server{CoordinatorURL: "https://other.example/register/new-token"}).configured()
	if err != nil || s.CoordinatorURL != "https://other.example" || s.Token != "new-token" {
		t.Fatalf("registration URL override did not carry its own token: %v", err)
	}
	if _, err := (Server{CoordinatorURL: c.Coordinator, Token: "conflicting-token"}).configured(); err == nil {
		t.Fatal("conflicting registration credentials accepted")
	}

	for _, tc := range []struct{ name, data string }{
		{"missing token", strings.Replace(string(data), "/register/config-token", "/register/", 1)},
		{"bad CA", strings.Replace(string(data), "ssh-ed25519", "not-a-key", 1)},
		{"unknown account", strings.Replace(string(data), account.Username, "no-such-portal-account", 1)},
		{"unknown field", strings.TrimSuffix(string(data), "}") + `,"unknown":true}`},
		{"trailing data", string(data) + `{}`},
		{"oversized", strings.Repeat(" ", 65537)},
		{"null", `null`},
		{"malformed", `{broken`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadServerConfig(path); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	if _, err := LoadServerConfig(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing explicit config accepted")
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadServerConfig(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("readable secret config accepted: %v", err)
		}
	}
}
