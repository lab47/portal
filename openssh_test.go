package portal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/relayserver"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func testOpenSSHKey(t *testing.T, path string, encrypted bool) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "test")
	if encrypted {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(private, "test", []byte("test-password"))
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	return signer, private
}

func TestOpenSSHKeyDiscovery(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	for _, name := range []string{"id_rsa", "id_ecdsa", "id_ed25519"} {
		path := filepath.Join(home, ".ssh", name)
		want, _ := testOpenSSHKey(t, path, false)
		got, close, err := openSSHSigner(context.Background(), "")
		if err != nil {
			t.Fatal(err)
		}
		close()
		if ssh.FingerprintSHA256(got.PublicKey()) != ssh.FingerprintSHA256(want.PublicKey()) {
			t.Fatalf("did not discover %s", name)
		}
	}
	chosen := filepath.Join(home, "custom")
	want, _ := testOpenSSHKey(t, chosen, false)
	got, close, err := openSSHSigner(context.Background(), chosen)
	if err != nil {
		t.Fatal(err)
	}
	close()
	if ssh.FingerprintSHA256(got.PublicKey()) != ssh.FingerprintSHA256(want.PublicKey()) {
		t.Fatal("explicit key did not win")
	}
	if _, _, err := openSSHSigner(context.Background(), chosen+"-missing"); err == nil {
		t.Fatal("missing explicit key silently fell back")
	}
	if err := os.WriteFile(chosen, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openSSHSigner(context.Background(), chosen); err == nil {
		t.Fatal("malformed explicit key silently fell back")
	}
}

func TestOpenSSHAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-domain SSH agent")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".ssh", "id_ed25519")
	want, private := testOpenSSHKey(t, path, true)
	otherSigner, other := testOpenSSHKey(t, filepath.Join(home, "other"), false)
	socket := filepath.Join(home, "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("SSH_AUTH_SOCK", socket)
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: other}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); agent.ServeAgent(keyring, conn) }()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, _, err := openSSHSigner(ctx, path); err == nil {
		t.Fatal("encrypted key accepted an unrelated agent key")
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	signer, close, err := openSSHSigner(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	proof := []byte("agent signing test")
	sig, err := signer.Sign(rand.Reader, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := want.PublicKey().Verify(proof, sig); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	signer, close2, err := openSSHSigner(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	defer close2()
	if ssh.FingerprintSHA256(signer.PublicKey()) != ssh.FingerprintSHA256(otherSigner.PublicKey()) {
		t.Fatal("agent-only discovery did not select first plain key")
	}
}

func TestOpenSSHAuthorizedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	signer, restricted := testSigner(t), testSigner(t)
	key := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	text := "# OpenSSH keys\n\n" + key + "restrict " + string(ssh.MarshalAuthorizedKey(restricted.PublicKey())) + "cert-authority " + string(ssh.MarshalAuthorizedKey(testSigner(t).PublicKey()))
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	auth, p, err := openSSHAuthentication(path)
	if err != nil {
		t.Fatal(err)
	}
	identity := ssh.FingerprintSHA256(signer.PublicKey())
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if len(auth.keys) != 1 || len(p) != 1 || len(p[identity]) != 1 || !p[identity][account.Uid] {
		t.Fatal("authorized keys expanded beyond the server account or unrestricted entries")
	}
	if _, err := p.authorize(identity, ""); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{"root", "nobody"} {
		if other, err := user.Lookup(candidate); err == nil && other.Uid != account.Uid {
			if _, err := p.authorize(identity, candidate); err == nil {
				t.Fatal("SSH key authorized another account")
			}
		}
	}
	for _, bad := range []string{"", "not a key", "restrict " + key, "command=\"echo hi\" " + key, "from=\"127.0.0.1\" " + key, "cert-authority " + key} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := openSSHAuthentication(path); err == nil {
			t.Fatalf("unsafe/empty key file accepted: %q", bad)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(path, []byte(key), 0600); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{path, filepath.Dir(path)} {
			if err := os.Chmod(name, 0777); err != nil {
				t.Fatal(err)
			}
			if _, _, err := openSSHAuthentication(path); err == nil {
				t.Fatal("writable trust path accepted")
			}
			if err := os.Chmod(name, 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestOpenSSHTargetAccountKeys(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" || current.Uid != "0" {
		t.Skip("cross-account trust fixtures require Unix root")
	}
	rootKey, appKey := testSigner(t), testSigner(t)
	root := &user.User{Uid: "0", Username: "root", HomeDir: t.TempDir()}
	app := &user.User{Uid: "1001", Username: "app", HomeDir: t.TempDir()}
	for _, fixture := range []struct {
		account *user.User
		key     ssh.Signer
	}{{root, rootKey}, {app, appKey}} {
		path := filepath.Join(fixture.account.HomeDir, ".ssh", "authorized_keys")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(fixture.key.PublicKey()), 0600); err != nil {
			t.Fatal(err)
		}
		if fixture.account == app {
			if err := os.Chown(path, 1001, -1); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A server-account override must never authorize another account.
	server := peerAuthenticator{openSSH: true, keyFile: filepath.Join(root.HomeDir, ".ssh", "authorized_keys")}
	proof := []byte("signed request")
	for _, target := range []*user.User{root, app} {
		auth, p, err := server.forSSHAccount(target, root)
		if err != nil {
			t.Fatal(err)
		}
		for _, signer := range []ssh.Signer{rootKey, appKey} {
			sig, err := signer.Sign(rand.Reader, proof)
			if err != nil {
				t.Fatal(err)
			}
			peer, err := auth.verify(signer.PublicKey().Marshal(), ssh.Marshal(sig), proof)
			want := (target == root && signer == rootKey) || (target == app && signer == appKey)
			if (err == nil) != want {
				t.Fatalf("target %s accepted wrong key: %v", target.Username, err)
			}
			if want && (!p[peer.KeyId][target.Uid] || len(p[peer.KeyId]) != 1) {
				t.Fatal("key permissions escaped the target account")
			}
		}
	}
	if _, _, err := server.forSSHAccount(root, app); err == nil {
		t.Fatal("non-root server accepted root account")
	}
	if err := os.Remove(filepath.Join(app.HomeDir, ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.forSSHAccount(app, root); err == nil {
		t.Fatal("missing target keys fell back to server keys")
	}
}

func TestOpenSSHQueryKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ssh", "query_keys")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	auth, _, err := (Server{AuthorizedKeysFile: path + ".missing", QueryAuthorizedKeysFile: path}).authentication(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	proof := monitorProof([]byte("nonce"), MonitorRequest{Source: "disk"})
	sig, err := signer.Sign(rand.Reader, proof)
	if err != nil {
		t.Fatal(err)
	}
	peer, p, err := auth.verifyQuery(signer.PublicKey().Marshal(), ssh.Marshal(sig), proof, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = authorizeMonitorSource(p, peer.KeyId, "disk")
	if (err == nil) != (os.Geteuid() == 0) {
		t.Fatalf("query delegation changed source privilege requirements: %v", err)
	}
	if _, _, err := auth.verifyQuery(signer.PublicKey().Marshal(), ssh.Marshal(sig), append(proof, 'x'), nil); err == nil {
		t.Fatal("query delegate bypassed signed request verification")
	}
	if _, _, err := auth.verifyQuery(testSigner(t).PublicKey().Marshal(), ssh.Marshal(sig), proof, nil); err == nil {
		t.Fatal("unknown query key was accepted")
	}
	if _, _, err := auth.verifyForAccount(signer.PublicKey().Marshal(), ssh.Marshal(sig), proof, "", nil); err == nil {
		t.Fatal("query keys leaked into command authentication")
	}
}

func TestOpenSSHProofs(t *testing.T) {
	signer, stranger, ca := testSigner(t), testSigner(t), testSigner(t)
	identity := ssh.FingerprintSHA256(signer.PublicKey())
	auth := peerAuthenticator{keys: map[string]ssh.PublicKey{identity: signer.PublicKey()}}
	nonce := []byte("challenge")
	command, err := signCommand(signer, signer.PublicKey(), nonce, "", []string{"echo", "hello"})
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := signMonitor(signer, signer.PublicKey(), nonce, MonitorRequest{Source: "process"})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := signRegisteredMonitor(signer, signer.PublicKey(), nonce, monitorAction{Action: "delete", ID: strings.Repeat("a", 32)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                         string
		credential, signature, proof []byte
	}{
		{"command", command.Certificate, command.Signature, commandProof(nonce, command.User, command.Argv)},
		{"monitor", monitor.Certificate, monitor.Signature, monitorProof(nonce, monitor.MonitorRequest)},
		{"registered", registered.Certificate, registered.Signature, registeredMonitorProof(nonce, registered.monitorAction)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer, err := auth.verify(tc.credential, tc.signature, tc.proof)
			if err != nil || peer.KeyId != identity {
				t.Fatalf("valid proof rejected: %v", err)
			}
			if _, err := auth.verify(tc.credential, tc.signature, append([]byte("changed"), tc.proof...)); err == nil {
				t.Fatal("modified/replayed proof accepted")
			}
			if _, err := auth.verify(stranger.PublicKey().Marshal(), tc.signature, tc.proof); err == nil {
				t.Fatal("unknown key accepted")
			}
			forged, err := stranger.Sign(rand.Reader, tc.proof)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := auth.verify(tc.credential, ssh.Marshal(forged), tc.proof); err == nil {
				t.Fatal("another key could sign as authorized identity")
			}
			if _, err := (peerAuthenticator{ca: ca.PublicKey(), principal: "admin"}).verify(tc.credential, tc.signature, tc.proof); err == nil {
				t.Fatal("certificate server accepted plain key")
			}
		})
	}
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	if _, err := auth.verify(cert.Marshal(), command.Signature, commandProof(nonce, command.User, command.Argv)); err == nil {
		t.Fatal("SSH key authentication accepted a certificate")
	}
	peer, err := verifyCommand(ca.PublicKey(), "admin", nonce, commandRequest{Certificate: cert.Marshal(), Signature: command.Signature, Argv: command.Argv})
	if err != nil || monitorOwner(peer.Key) != monitorOwner(signer.PublicKey()) {
		t.Fatalf("certificate ownership changed: %v", err)
	}
}

func TestOpenSSHClientProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	keyPath := filepath.Join(dir, ".ssh", "id_ed25519")
	signer, _ := testOpenSSHKey(t, keyPath, false)
	otherPath := filepath.Join(dir, "other")
	other, _ := testOpenSSHKey(t, otherPath, false)
	queryKeyPath := filepath.Join(dir, "query-key")
	querySigner, _ := testOpenSSHKey(t, queryKeyPath, false)
	queryKeys := filepath.Join(dir, ".ssh", "query_authorized_keys")
	if err := os.WriteFile(queryKeys, ssh.MarshalAuthorizedKey(querySigner.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(dir, ".ssh", "authorized_keys")
	data := append(ssh.MarshalAuthorizedKey(signer.PublicKey()), ssh.MarshalAuthorizedKey(other.PublicKey())...)
	if err := os.WriteFile(authorized, data, 0600); err != nil {
		t.Fatal(err)
	}
	auth, p, err := (Server{AuthorizedKeysFile: authorized, QueryAuthorizedKeysFile: queryKeys}).authentication(ctx)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := httptest.NewServer(NewCoordinator("test-secret"))
	defer coordinator.Close()
	relayHTTP := httptest.NewServer(relayserver.New())
	defer relayHTTP.Close()
	relayURL, err := netaddr.ParseRelayURL(relayHTTP.URL)
	if err != nil {
		t.Fatal(err)
	}
	server, err := iroh.Bind(ctx, iroh.WithALPNs(alpn), iroh.WithRelayMode(relay.ModeCustomURLs(relayURL)), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	if err := server.Online(ctx); err != nil {
		t.Fatal(err)
	}
	reg := registration{Name: "quick-node", EndpointID: server.ID().String(), RelayURL: relayURL.String()}
	if err := register(ctx, coordinator.URL, "test-secret", reg); err != nil {
		t.Fatal(err)
	}
	go serveWithSource(ctx, server, auth, p, func(ctx context.Context, _ MonitorRequest, emit func(Event) error) error {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				if err := emit(Event{PID: 42, Syscall: 3, Time: now}); err != nil {
					return err
				}
			case <-ctx.Done():
				return nil
			}
		}
	})
	configPath := filepath.Join(dir, "client.json")
	config, err := json.Marshal(ClientConfig{Coordinator: coordinator.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	c := Client{Name: reg.Name, ConfigFile: configPath}
	if runtime.GOOS != "windows" {
		result, err := c.Run(ctx, []string{"/bin/echo", "ssh-key"})
		if err != nil || result.Error != "" || result.Output != "ssh-key\n" || result.ExitCode != 0 {
			t.Fatalf("command: %+v, %v", result, err)
		}
	}
	docs, err := c.Capabilities(ctx)
	if err != nil || len(docs.Sources) != 14 {
		t.Fatalf("capabilities: %+v, %v", docs, err)
	}
	snapshot, err := c.Query(ctx, MonitorRequest{Source: "process", Mode: "snapshot", PID: uint32(os.Getpid())})
	if err != nil || len(snapshot.Processes) != 1 || snapshot.Processes[0].PID != uint32(os.Getpid()) {
		t.Fatalf("snapshot: %+v, %v", snapshot, err)
	}
	request := MonitorRequest{Source: "syscalls", PID: 42}
	stop := errors.New("read one")
	delegate := c
	delegate.KeyFile = queryKeyPath
	if _, err := delegate.Capabilities(ctx); err != nil {
		t.Fatalf("query delegate capabilities: %v", err)
	}
	if snapshot, err := delegate.Query(ctx, MonitorRequest{Source: "process", Mode: "snapshot", PID: uint32(os.Getpid())}); err != nil || len(snapshot.Processes) != 1 {
		t.Fatalf("query delegate snapshot: %+v, %v", snapshot, err)
	}
	if runtime.GOOS != "windows" {
		for _, target := range []string{"", "root"} {
			delegate.User = target
			result, err := delegate.Run(ctx, []string{"/bin/echo", "should-not-run"})
			if err != nil || result.Error != "authentication failed" || result.Output != "" {
				t.Fatalf("query delegate ran command as %q: %+v, %v", target, result, err)
			}
		}
		delegate.User = ""
	}
	if err := delegate.Monitor(ctx, request, func(event Event) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("query delegate stream: %v", err)
	}
	delegatedID, err := delegate.CreateMonitor(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := delegate.ReadMonitor(ctx, delegatedID, 0, func(record MonitorRecord) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("query delegate registered read: %v", err)
	}
	if err := c.DeleteMonitor(ctx, delegatedID); err == nil {
		t.Fatal("command-authorized key deleted delegate's monitor")
	}
	if err := delegate.DeleteMonitor(ctx, delegatedID); err != nil {
		t.Fatal(err)
	}
	delegatedID, err = delegate.CreateMonitor(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(queryKeys, ssh.MarshalAuthorizedKey(other.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := delegate.Query(ctx, MonitorRequest{Source: "process", Mode: "snapshot"}); err == nil {
		t.Fatal("revoked query delegate could still query")
	}
	if err := delegate.ReadMonitor(ctx, delegatedID, 0, func(record MonitorRecord) error { return stop }); err == nil || errors.Is(err, stop) {
		t.Fatalf("revoked query delegate could still read: %v", err)
	}
	if err := delegate.DeleteMonitor(ctx, delegatedID); err == nil {
		t.Fatal("revoked query delegate could still delete")
	}
	if err := c.Monitor(ctx, request, func(event Event) error {
		if event.PID != 42 {
			t.Errorf("wrong streamed event: %+v", event)
		}
		return stop
	}); !errors.Is(err, stop) {
		t.Fatalf("stream: %v", err)
	}
	id, err := c.CreateMonitor(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	var last uint64
	for i := 0; i < 2; i++ {
		if err := c.ReadMonitor(ctx, id, last, func(record MonitorRecord) error {
			if record.Sequence <= last || record.Event.PID != 42 {
				t.Errorf("bad resume: %+v", record)
			}
			last = record.Sequence
			return stop
		}); !errors.Is(err, stop) {
			t.Fatalf("read/resume: %v", err)
		}
	}
	stranger := c
	stranger.KeyFile = otherPath
	if err := stranger.DeleteMonitor(ctx, id); err == nil {
		t.Fatal("another authorized key deleted owner's monitor")
	}
	if err := c.DeleteMonitor(ctx, id); err != nil {
		t.Fatal(err)
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		c.User = account.Username
		result, err := c.Run(ctx, []string{"/usr/bin/id", "-u"})
		if err != nil || result.Error != "" || strings.TrimSpace(result.Output) != account.Uid {
			t.Fatalf("explicit target account: %+v, %v", result, err)
		}
		c.User = "portal-nonexistent-account"
		result, err = c.Run(ctx, []string{"/bin/echo", "should-not-run"})
		if err != nil || result.Error != "authentication failed" || result.Output != "" {
			t.Fatalf("unknown target account: %+v, %v", result, err)
		}
		c.User = ""
	}
	if err := os.WriteFile(authorized, ssh.MarshalAuthorizedKey(other.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Query(ctx, MonitorRequest{Source: "process", Mode: "snapshot"}); err == nil {
		t.Fatal("revoked key could still query")
	}
	if _, err := c.CreateMonitor(ctx, request, time.Minute); err == nil {
		t.Fatal("revoked key could still register a monitor")
	}
	if runtime.GOOS != "windows" {
		result, err := c.Run(ctx, []string{"/bin/echo", "should-not-run"})
		if err != nil || result.Error != "authentication failed" || result.Output != "" {
			t.Fatalf("revoked key could run a command: %+v, %v", result, err)
		}
	}
	if _, err := stranger.Query(ctx, MonitorRequest{Source: "process", Mode: "snapshot"}); err != nil {
		t.Fatalf("remaining key stopped working: %v", err)
	}
}

func TestOpenSSHConfiguredServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	signer, _ := testOpenSSHKey(t, filepath.Join(dir, ".ssh", "id_ed25519"), false)
	authorized := filepath.Join(dir, ".ssh", "authorized_keys")
	if err := os.WriteFile(authorized, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	coordinator := httptest.NewServer(NewCoordinator("test-secret"))
	defer coordinator.Close()
	relayHTTP := httptest.NewServer(relayserver.New())
	defer relayHTTP.Close()
	config := ServerConfig{Name: "configured-ssh-node", Coordinator: coordinator.URL + "/register/test-secret", Relay: relayHTTP.URL, AuthorizedKeys: ".ssh/authorized_keys", QueryAuthorizedKeys: ".ssh/query_authorized_keys"}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "server.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- (Server{ConfigFile: path}).Serve(ctx) }()
	for {
		if _, err := lookup(ctx, coordinator.URL, config.Name); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("startup failed: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	c := Client{Name: config.Name, CoordinatorURL: coordinator.URL}
	snapshot, err := c.Query(ctx, MonitorRequest{Source: "process", Mode: "snapshot", PID: uint32(os.Getpid())})
	if err != nil || len(snapshot.Processes) != 1 {
		t.Fatalf("configured server query: %+v, %v", snapshot, err)
	}
	// Delegation still works when the server account has no command keys.
	if err := os.Rename(authorized, filepath.Join(dir, ".ssh", "query_authorized_keys")); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := c.Query(ctx, MonitorRequest{Source: "process", Mode: "snapshot", PID: uint32(os.Getpid())}); err != nil || len(snapshot.Processes) != 1 {
		t.Fatalf("config-only query delegation: %+v, %v", snapshot, err)
	}
	for _, mixed := range []Server{
		{CAFile: "missing-ca.pub", AuthorizedKeysFile: authorized}, {CAPublicKey: "invalid-key", AuthorizedKeysFile: authorized},
		{CAFile: "missing-ca.pub", QueryAuthorizedKeysFile: authorized}, {CAPublicKey: "invalid-key", QueryAuthorizedKeysFile: authorized},
		{PolicyFile: "policy.json"}, {Identities: map[string][]string{"operator": {"root"}}},
		{Principal: "admin"},
	} {
		if _, _, err := mixed.authentication(ctx); err == nil {
			t.Fatal("mixed trust modes accepted")
		}
	}
	for _, mixed := range []Client{
		{CertFile: "cert"}, {CAURL: "https://ca.example"}, {Principal: "admin"},
		{RefreshTokenFile: "token"},
	} {
		if _, err := mixed.configured(); err == nil {
			t.Fatal("certificate options accepted without a CA")
		}
	}
	// A sudo caller's inherited HOME must never supply root's trust keys.
	auth, _, err := openSSHAuthentication("")
	if err == nil && auth.keys[ssh.FingerprintSHA256(signer.PublicKey())] != nil {
		t.Fatal("server inherited client HOME instead of effective account home")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestAuthenticationSelectionDoesNotDowngrade(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	path := filepath.Join(dir, ".ssh", "id_ed25519")
	signer, _ := testOpenSSHKey(t, path, false)
	ca := testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	if err := os.WriteFile(path+"-cert.pub", ssh.MarshalAuthorizedKey(cert), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := (Client{KeyFile: path}).configured()
	if err != nil || c.CertFile != "" || c.Principal != "" || c.RefreshTokenFile != "" {
		t.Fatalf("certificate sidecar enabled certificate mode without CA: %+v, %v", c, err)
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing-ca.pub")
	bad := filepath.Join(dir, "bad-ca.pub")
	if err := os.WriteFile(bad, []byte("not a CA key"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, caPath := range []string{missing, bad} {
		c, err := (Client{KeyFile: path, CAFile: caPath}).configured()
		if err != nil || c.CertFile != path+"-cert.pub" {
			t.Fatalf("CA did not select certificates: %+v, %v", c, err)
		}
		if _, _, err := c.clientSigner(t.Context()); err == nil {
			t.Fatal("client ignored invalid configured CA")
		}
		if _, _, err := (Server{CAFile: caPath, Principal: "admin", Identities: map[string][]string{"operator": {account.Username}}}).authentication(t.Context()); err == nil {
			t.Fatal("server ignored invalid configured CA")
		}
	}
	s, err := (Server{CAPublicKey: string(ssh.MarshalAuthorizedKey(ca.PublicKey())), Identities: map[string][]string{"operator": {account.Username}}}).configured()
	if err != nil {
		t.Fatal(err)
	}
	auth, _, err := s.authentication(t.Context())
	if err != nil || auth.ca == nil || len(auth.keys) != 0 || s.Principal != "admin" {
		t.Fatalf("inline CA did not select certificates: %v", err)
	}
}
