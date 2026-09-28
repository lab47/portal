package portal_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/lab47/portal"
	"github.com/tmc/go-iroh/relayserver"
	"golang.org/x/crypto/ssh"
)

func TestPackageAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	coord := httptest.NewServer(portal.NewCoordinator("test-token"))
	defer coord.Close()
	relay := httptest.NewServer(relayserver.New())
	defer relay.Close()

	makeSigner := func() (ssh.Signer, ed25519.PrivateKey) {
		t.Helper()
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return signer, key
	}
	ca, _ := makeSigner()
	operator, private := makeSigner()
	cert := &ssh.Certificate{
		Key: operator.PublicKey(), CertType: ssh.UserCert, KeyId: "operator", ValidPrincipals: []string{"admin"},
		ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caFile := write("ca.pub", ssh.MarshalAuthorizedKey(ca.PublicKey()))
	certFile := write("operator-cert.pub", ssh.MarshalAuthorizedKey(cert))
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	policyData, err := json.Marshal(map[string]any{"identities": map[string][]string{"operator": {account.Username}}})
	if err != nil {
		t.Fatal(err)
	}
	policyFile := write("policy.json", policyData)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := write("operator", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))

	done := make(chan error, 1)
	go func() {
		done <- (portal.Server{
			Name: "node-a", CoordinatorURL: coord.URL, Token: "test-token", CAFile: caFile,
			Principal: "admin", PolicyFile: policyFile, RelayURL: relay.URL, Listen: "127.0.0.1:0",
		}).Serve(ctx)
	}()
	// Wait for the server's first check-in; Serve returns early if it fails.
	for {
		res, err := coord.Client().Get(coord.URL + "/servers/node-a")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode == 200 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("server stopped before check-in: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	result, err := (portal.Client{
		Name: "node-a", CoordinatorURL: coord.URL, KeyFile: keyFile, CertFile: certFile,
	}).Run(ctx, []string{"/bin/echo", "package-api"})
	if err != nil || result.Output != "package-api\n" || result.ExitCode != 0 || result.Error != "" {
		t.Fatalf("package client result: %+v, %v", result, err)
	}
	result, err = (portal.Client{
		Name: "node-a", CoordinatorURL: coord.URL, KeyFile: keyFile, CertFile: certFile, User: account.Username,
	}).Run(ctx, []string{"/usr/bin/id", "-un"})
	if err != nil || result.Output != account.Username+"\n" || result.Error != "" {
		t.Fatalf("package client target user: %+v, %v", result, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
