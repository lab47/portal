package portal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoordinatorConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	if _, err := LoadCoordinatorConfig(""); err != nil {
		t.Fatal(err)
	}
	path, err := DefaultCoordinatorConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"url":"https://inventory.example","token":"paired-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCoordinatorConfig("")
	if err != nil || c.URL != "https://inventory.example" || c.Token != "paired-secret" {
		t.Fatalf("coordinator pair not loaded: %v", err)
	}
	for _, data := range []string{
		`{"url":"https://inventory.example"}`, `{"token":"secret"}`,
		`{"url":"ftp://inventory.example","token":"secret"}`,
		`{"url":"https://user:secret@inventory.example","token":"secret"}`,
		`{"url":"https://inventory.example","token":"secret","unknown":true}`,
		`{"url":"https://inventory.example","token":"secret"} {}`, `null`, strings.Repeat(" ", 65537),
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCoordinatorConfig(path); err == nil {
			t.Fatal("invalid coordinator bundle accepted")
		}
	}
	if _, err := LoadCoordinatorConfig(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing explicit coordinator bundle accepted")
	}
}

func TestCoordinatorRegistrationURL(t *testing.T) {
	for _, tc := range []struct{ base, token, encoded string }{
		{"https://inventory.example", "aB-123_", "https://inventory.example/register/aB-123_"},
		{"http://127.0.0.1:8080/portal", "secret", "http://127.0.0.1:8080/portal/register/secret"},
		{"https://inventory.example/api%2Fedge", "a?b#c%", "https://inventory.example/api%2Fedge/register/a%3Fb%23c%25"},
	} {
		c := CoordinatorConfig{URL: tc.base, Token: tc.token}
		encoded, err := c.RegistrationURL()
		if err != nil || encoded != tc.encoded {
			t.Fatalf("encoding: %v", err)
		}
		parsed, err := ParseCoordinatorURL(tc.encoded)
		if err != nil || parsed != c {
			t.Fatalf("registration URL changed base or token: %v", err)
		}
	}
	for _, input := range []string{
		"https://inventory.example", "https://inventory.example/register/",
		"https://inventory.example/register/do-not-print/extra",
		"https://inventory.example/register/do-not-print%2Fextra",
		"https://inventory.example/register/do-not-print%0A",
		"https://inventory.example/register/..",
		"https://inventory.example/register/do-not-print?query=1",
		"https://inventory.example/register/do-not-print#fragment",
		"https://user:do-not-print@inventory.example/register/secret",
		"https://inventory.example/register/do-not-print%zz",
		"ftp://inventory.example/register/do-not-print",
		"https://inventory.example/register/first/register/do-not-print",
	} {
		if _, err := ParseCoordinatorURL(input); err == nil || strings.Contains(err.Error(), "do-not-print") {
			t.Fatalf("invalid registration URL accepted or exposed its token: %v", err)
		}
	}
}
