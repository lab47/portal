package adminhelper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/relayserver"
	"golang.org/x/crypto/ssh"
)

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func testCertificate(t *testing.T, signer, ca ssh.Signer, identity, principal string, expiry time.Time) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key: signer.PublicKey(), CertType: ssh.UserCert, KeyId: identity,
		ValidPrincipals: []string{principal}, ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore: uint64(expiry.Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestCoordinatorIrohCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	coordinator := httptest.NewServer(NewCoordinator("registration-secret"))
	defer coordinator.Close()
	relayHTTP := httptest.NewServer(relayserver.New())
	defer relayHTTP.Close()
	relayURL, err := netaddr.ParseRelayURL(relayHTTP.URL)
	if err != nil {
		t.Fatal(err)
	}
	mode := relay.ModeCustomURLs(relayURL)
	server, err := iroh.Bind(ctx, iroh.WithALPNs(alpn), iroh.WithRelayMode(mode), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	if err := server.Online(ctx); err != nil {
		t.Fatal(err)
	}
	reg := registration{Name: "node-a", EndpointID: server.ID().String(), RelayURL: server.Addr().RelayURLs()[0].String()}
	if err := register(ctx, coordinator.URL, "bad-token", reg); err == nil {
		t.Fatal("unauthorized check-in succeeded")
	}
	if err := register(ctx, coordinator.URL, "registration-secret", reg); err != nil {
		t.Fatal(err)
	}
	found, err := lookup(ctx, coordinator.URL, reg.Name)
	if err != nil || found.EndpointID != reg.EndpointID || found.RelayURL != reg.RelayURL {
		t.Fatalf("lookup: %+v, %v", found, err)
	}
	data, err := json.Marshal(found)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"address"`) || len(server.Addr().IPAddrs()) == 0 {
		t.Fatalf("inventory leaked an address or server lacks a direct candidate: %s", data)
	}
	ca := testSigner(t)
	signer := testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	allowed := policy{"operator": {fmt.Sprint(os.Geteuid()): true}}
	if os.Geteuid() == 0 {
		if nobody, err := user.Lookup("nobody"); err == nil {
			allowed["operator"][nobody.Uid] = true
		}
	}
	done := make(chan error, 1)
	go func() { done <- serve(ctx, server, ca.PublicKey(), "admin", allowed) }()
	client, err := iroh.Bind(ctx, iroh.WithRelayMode(mode), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(context.Background())
	if err := client.Online(ctx); err != nil {
		t.Fatal(err)
	}
	response, err := runRemote(ctx, client, found, signer, cert, "", []string{"/bin/echo", "from-iroh"})
	if err != nil || response.Output != "from-iroh\n" || response.ExitCode != 0 || response.Error != "" {
		t.Fatalf("command: %+v, %v", response, err)
	}
	response, err = runRemote(ctx, client, found, signer, cert, "", []string{"/bin/sh", "-c", "printf failure; exit 7"})
	if err != nil || response.Output != "failure" || response.ExitCode != 7 {
		t.Fatalf("exit status: %+v, %v", response, err)
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	response, err = runRemote(ctx, client, found, signer, cert, account.Username, []string{"/usr/bin/id", "-u"})
	if err != nil || response.Error != "" || response.Output != fmt.Sprintf("%d\n", os.Geteuid()) {
		t.Fatalf("run as current user: %+v, %v", response, err)
	}
	t.Setenv("ADMINHELPER_TOKEN", "server-only-secret")
	response, err = runRemote(ctx, client, found, signer, cert, account.Username, []string{"/usr/bin/env"})
	if err != nil || response.Error != "" || strings.Contains(response.Output, "server-only-secret") || !strings.Contains(response.Output, "USER="+account.Username+"\n") {
		t.Fatalf("target user environment: %+v, %v", response, err)
	}
	response, err = runRemote(ctx, client, found, signer, cert, "no-such-adminhelper-user", []string{"/bin/echo", "should-not-run"})
	if err != nil || response.Output != "" || !strings.Contains(response.Error, "unknown target user") {
		t.Fatalf("unknown user command: %+v, %v", response, err)
	}
	if os.Geteuid() != 0 {
		response, err = runRemote(ctx, client, found, signer, cert, "root", []string{"/bin/echo", "should-not-run"})
		if err != nil || response.Output != "" || response.Error != "not authorized for target user" {
			t.Fatalf("unauthorized root command: %+v, %v", response, err)
		}
	} else if nobody, err := user.Lookup("nobody"); err == nil {
		response, err = runRemote(ctx, client, found, signer, cert, nobody.Username, []string{"/usr/bin/id", "-u"})
		if err != nil || response.Error != "" || response.Output != nobody.Uid+"\n" {
			t.Fatalf("root-to-user switch: %+v, %v", response, err)
		}
	}
	for _, tc := range []struct {
		name string
		cert *ssh.Certificate
		key  ssh.Signer
	}{
		{"wrong principal", testCertificate(t, signer, ca, "operator", "other", time.Now().Add(time.Hour)), signer},
		{"expired", testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(-time.Second)), signer},
		{"wrong CA", testCertificate(t, signer, testSigner(t), "operator", "admin", time.Now().Add(time.Hour)), signer},
		{"wrong private key", cert, testSigner(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, err := runRemote(ctx, client, found, tc.key, tc.cert, "", []string{"/bin/echo", "should-not-run"})
			if err != nil || response.Error != "authentication failed" || response.Output != "" {
				t.Fatalf("rejected command: %+v, %v", response, err)
			}
		})
	}
	for _, identity := range []string{"other-operator", ""} {
		otherCert := testCertificate(t, signer, ca, identity, "admin", time.Now().Add(time.Hour))
		response, err := runRemote(ctx, client, found, signer, otherCert, account.Username, []string{"/bin/echo", "should-not-run"})
		if err != nil || response.Output != "" || response.Error == "" {
			t.Fatalf("unauthorized identity %q: %+v, %v", identity, response, err)
		}
	}
	// Inventory contains no IP, so the initial dial must use the relay. Iroh
	// exchanges direct candidates on that connection and can upgrade it.
	directClient, err := iroh.Bind(ctx, iroh.WithRelayMode(mode), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer directClient.Shutdown(context.Background())
	if err := directClient.Online(ctx); err != nil {
		t.Fatal(err)
	}
	conn, err := directClient.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL), alpn)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range conn.Paths() {
		if !path.Relayed {
			t.Fatalf("initial path unexpectedly direct: %+v", path)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	upgraded := false
	for time.Now().Before(deadline) && !upgraded {
		for _, path := range conn.Paths() {
			if !path.Relayed && path.Selected && path.Validated {
				upgraded = true
				break
			}
		}
		if !upgraded {
			time.Sleep(250 * time.Millisecond)
		}
	}
	if !upgraded {
		t.Errorf("iroh did not select a direct path: %+v", conn.Paths())
	}
	conn.CloseWithError(0, "")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCommandProofBindsArguments(t *testing.T) {
	ca, signer := testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	nonce := []byte(strings.Repeat("n", 32))
	req, err := signCommand(signer, cert, nonce, "deploy", []string{"echo", "safe"})
	if err != nil {
		t.Fatal(err)
	}
	req.Argv = []string{"echo", "unsafe"}
	if _, err := verifyCommand(ca.PublicKey(), "admin", nonce, req); err == nil {
		t.Fatal("modified arguments passed authentication")
	}
	req.Argv = []string{"echo", "safe"}
	req.User = "root"
	if _, err := verifyCommand(ca.PublicKey(), "admin", nonce, req); err == nil {
		t.Fatal("modified target user passed authentication")
	}
	req.User = "deploy"
	if _, err := verifyCommand(ca.PublicKey(), "admin", []byte(strings.Repeat("x", 32)), req); err == nil {
		t.Fatal("replayed signature passed authentication")
	}
}
