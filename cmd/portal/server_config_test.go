package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lab47/portal"
	"github.com/tmc/go-iroh/relayserver"
)

func TestServerInitAndConfigOnlyServing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("PORTAL_TOKEN", "ignored-environment-token")
	ca := filepath.Join(dir, "ca")
	key := filepath.Join(dir, "operator")
	for _, path := range []string{ca, key} {
		if err := generateKey(path); err != nil {
			t.Fatal(err)
		}
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"coordinator", "--listen", "not-an-address"}); err == nil || !strings.Contains(err.Error(), "registration token required") {
		t.Fatalf("coordinator used an environment token instead of requiring config: %v", err)
	}
	coordinator := httptest.NewUnstartedServer(nil)
	coordinatorURL := "http://" + coordinator.Listener.Addr().String()
	if err := run([]string{"coordinator", "init", "--url", coordinatorURL}); err != nil {
		t.Fatal(err)
	}
	coordinatorPath, err := portal.DefaultCoordinatorConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := portal.LoadCoordinatorConfig(coordinatorPath)
	if err != nil || bundle.URL != coordinatorURL || len(bundle.Token) != 64 {
		t.Fatalf("coordinator bundle not generated correctly: %v", err)
	}
	if err := run([]string{"coordinator", "--config", coordinatorPath, "--listen", "not-an-address"}); err == nil || !strings.Contains(err.Error(), "missing port") {
		t.Fatalf("coordinator did not load its bundle before listening: %v", err)
	}
	if err := run([]string{"coordinator", "init", "--url", coordinatorURL}); err == nil {
		t.Fatal("coordinator init overwrote registration credentials")
	}
	registrationURL, err := bundle.RegistrationURL()
	if err != nil {
		t.Fatal(err)
	}
	handler := portal.NewCoordinator(bundle.Token)
	coordinator.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.String(), bundle.Token) || strings.Contains(r.URL.Path, "/register/") {
			t.Error("registration credential leaked into HTTP request URL")
		}
		handler.ServeHTTP(w, r)
	})
	coordinator.Start()
	defer coordinator.Close()
	relay := httptest.NewServer(relayserver.New())
	defer relay.Close()
	authority, err := portal.NewCA("https://ca.example.com", "operator", "admin", ca, filepath.Join(dir, "ca-state"), strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	caHTTP := httptest.NewTLSServer(authority.Handler("https://ca.example.com"))
	defer caHTTP.Close()
	previousClient := http.DefaultClient
	http.DefaultClient = caHTTP.Client()
	t.Cleanup(func() { http.DefaultClient = previousClient })
	args := []string{"server", "init", "--name", "node-a", "--coordinator", registrationURL,
		"--ca", caHTTP.URL + "/ca.pub", "--identity", "operator", "--user", account.Username}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	path, err := portal.DefaultServerConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	c, err := portal.LoadServerConfig(path)
	if err != nil || c.Coordinator != registrationURL || c.Name != "node-a" || c.Principal != "admin" || c.Identities["operator"][0] != account.Username {
		t.Fatalf("init did not save settings: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatalf("config permissions: %v, %v", info, err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(args); err == nil {
		t.Fatal("init overwrote server config")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("init modified existing config")
	}
	caHTTP.Close() // Startup must use the embedded key even with the CA offline.
	http.DefaultClient = previousClient
	// Only server.json is needed after initialization. Keep the CA private key
	// for signing, but remove both imported files and leave a conflicting env var.
	if err := os.Remove(ca + ".pub"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(coordinatorPath); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"server", "--config", path, "--policy", filepath.Join(dir, "missing-policy")}); err == nil || !strings.Contains(err.Error(), "missing-policy") {
		t.Fatalf("CLI failed to apply config or policy override: %v", err)
	}
	if err := run([]string{"server", "--ca", filepath.Join(dir, "missing-ca")}); err == nil || !strings.Contains(err.Error(), "missing-ca") {
		t.Fatalf("CLI failed to use default config or CA override: %v", err)
	}
	cert := key + "-cert.pub"
	if err := issueCertificate(ca, key+".pub", "admin", "operator", cert, time.Hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- (portal.Server{RelayURL: relay.URL, Listen: "127.0.0.1:0"}).Serve(ctx)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	}()
	for {
		res, err := coordinator.Client().Get(coordinator.URL + "/servers/node-a")
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(res.Body)
		res.Body.Close()
		if readErr != nil || strings.Contains(string(body), bundle.Token) {
			t.Fatal("inventory read failed or exposed registration token")
		}
		if res.StatusCode == 200 {
			break
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("server failed before check-in: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if runtime.GOOS == "windows" {
		return // Command below is Unix-specific; registration is cross-platform.
	}
	client := portal.Client{Name: "node-a", CoordinatorURL: coordinator.URL, KeyFile: key, CertFile: cert}
	result, err := client.Run(ctx, []string{"/bin/echo", "single-config"})
	if err != nil || result.Output != "single-config\n" || result.ExitCode != 0 || result.Error != "" {
		t.Fatalf("config-only server command: %+v, %v", result, err)
	}
	deniedCert := filepath.Join(dir, "denied-cert.pub")
	if err := issueCertificate(ca, key+".pub", "admin", "other", deniedCert, time.Hour); err != nil {
		t.Fatal(err)
	}
	client.CertFile = deniedCert
	result, err = client.Run(ctx, []string{"/bin/echo", "should-not-run"})
	if err != nil || result.Error != "not authorized for target user" || result.Output != "" {
		t.Fatalf("inline policy did not reject unauthorized identity: %+v, %v", result, err)
	}
}
