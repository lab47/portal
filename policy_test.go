package portal

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyAuthorization(t *testing.T) {
	current, err := user.LookupId(fmt.Sprint(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	data := fmt.Sprintf(`{"identities":{"operator":[%q]}}`, current.Username)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := loadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"", current.Username} {
		if account, err := p.authorize("operator", target); err != nil || account.Uid != current.Uid {
			t.Fatalf("operator target %q: %+v, %v", target, account, err)
		}
		for _, identity := range []string{"other", ""} {
			if _, err := p.authorize(identity, target); err == nil {
				t.Fatalf("identity %q allowed as %q", identity, target)
			}
		}
	}
	// A valid certificate cannot request an account missing from its policy.
	other := "root"
	if os.Geteuid() == 0 {
		other = "nobody"
		if _, err := user.Lookup(other); err != nil {
			t.Skip("no nobody account")
		}
	}
	if _, err := p.authorize("operator", other); err == nil {
		t.Fatalf("operator authorized as %s", other)
	}
	if os.Geteuid() == 0 {
		data := fmt.Sprintf(`{"identities":{"operator":[%q]}}`, other)
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		p, err = loadPolicy(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.authorize("operator", ""); err == nil {
			t.Fatal("implicit root allowed without root in policy")
		}
		if _, err := p.authorize("operator", "root"); err == nil {
			t.Fatal("explicit root allowed without root in policy")
		}
	}
}

func TestPolicyValidation(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if _, err := loadPolicy(path); err == nil {
		t.Fatal("missing policy accepted")
	}
	for _, tc := range []struct{ name, data string }{
		{"empty", `{}`},
		{"unknown field", `{"identities":{"operator":["root"]},"allowAll":true}`},
		{"empty identity", `{"identities":{"": ["root"]}}`},
		{"empty users", `{"identities":{"operator":[]}}`},
		{"unknown account", `{"identities":{"operator":["no-such-portal-user"]}}`},
		{"trailing document", fmt.Sprintf(`{"identities":{"operator":[%q]}} {}`, current.Username)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadPolicy(path); err == nil {
				t.Fatalf("invalid policy accepted: %s", tc.data)
			}
		})
	}
	if err := (Server{CAFile: "ca.pub", PolicyFile: ""}).Serve(t.Context()); err == nil || !strings.Contains(err.Error(), "policy file") {
		t.Fatalf("server allowed without policy: %v", err)
	}
}
