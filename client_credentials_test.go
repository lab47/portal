package portal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testClientCredentials(t *testing.T, expiry time.Time) (Client, *CA, *atomic.Int32, *httptest.Server) {
	t.Helper()
	ca, _, _ := testCA(t)
	dir := t.TempDir()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	c := Client{KeyFile: filepath.Join(dir, "client"), CertFile: filepath.Join(dir, "client-cert.pub"), CAFile: filepath.Join(dir, "ca.pub"), Principal: "admin", ConfigFile: filepath.Join(dir, "config.json"), Name: "node"}
	c.RefreshTokenFile = c.KeyFile + ".refresh"
	cert := testCertificate(t, signer, ca.signer, "operator", "admin", expiry)
	cert.ValidAfter = uint64(time.Now().Add(-48 * time.Hour).Unix())
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatal(err)
	}
	const token = "0123456789abcdefghijklmnopqrstuv"
	for path, data := range map[string][]byte{c.KeyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), c.CertFile: ssh.MarshalAuthorizedKey(cert), c.CAFile: ssh.MarshalAuthorizedKey(ca.signer.PublicKey()), c.RefreshTokenFile: []byte(token)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ca.user.Refresh = []caRefresh{{Hash: sha256.Sum256([]byte(token)), KeyHash: sha256.Sum256(signer.PublicKey().Marshal()), Expires: time.Now().Add(24 * time.Hour)}}
	calls := new(atomic.Int32)
	handler := ca.Handler("https://ca.example.com")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/refresh" {
			calls.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	previous := http.DefaultClient
	http.DefaultClient = server.Client()
	t.Cleanup(func() { http.DefaultClient = previous })
	c.CAURL, c.CoordinatorURL = server.URL, server.URL
	config, err := json.Marshal(ClientConfig{Key: c.KeyFile, Cert: c.CertFile, CA: c.CAFile, CAURL: c.CAURL, Coordinator: c.CoordinatorURL, RefreshToken: c.RefreshTokenFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.ConfigFile, config, 0600); err != nil {
		t.Fatal(err)
	}
	return c, ca, calls, server
}

func TestClientCertificateRefresh(t *testing.T) {
	for _, tc := range []struct {
		name      string
		remaining time.Duration
		renew     bool
	}{
		{"healthy", 6 * time.Minute, false}, {"boundary", 5 * time.Minute, true}, {"near expiry", time.Minute, true}, {"expired", -time.Hour, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ca, calls, _ := testClientCredentials(t, time.Now().Add(tc.remaining))
			before, _ := os.ReadFile(c.CertFile)
			_, cert, err := c.clientSigner(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyUserCertificate(ca.signer.PublicKey(), "admin", cert); err != nil {
				t.Fatal(err)
			}
			if (calls.Load() == 1) != tc.renew || calls.Load() > 1 {
				t.Fatalf("wrong renewal count: %d", calls.Load())
			}
			after, _ := os.ReadFile(c.CertFile)
			if bytes.Equal(before, after) == tc.renew {
				t.Fatal("certificate persistence did not match renewal")
			}
			if tc.renew {
				token, _ := os.ReadFile(c.RefreshTokenFile)
				if sha256.Sum256(token) != ca.user.Refresh[0].Hash || len(token) != 32 {
					t.Fatal("rotated token was not saved")
				}
				info, _ := os.Stat(c.RefreshTokenFile)
				if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
					t.Fatal("token permissions changed")
				}
			}
			if _, _, err := c.clientSigner(context.Background()); err != nil {
				t.Fatal(err)
			}
			if calls.Load() > 1 {
				t.Fatal("healthy renewed certificate refreshed again")
			}
		})
	}
	if certificateNeedsRefresh(&ssh.Certificate{ValidBefore: ssh.CertTimeInfinity}) {
		t.Fatal("infinite certificate needs refresh")
	}
}

func TestClientRefreshErrorsPreserveCredentials(t *testing.T) {
	for _, scenario := range []string{"untrusted", "principal", "future", "token expired", "missing token", "permissions", "no renewal config", "untrusted response"} {
		t.Run(scenario, func(t *testing.T) {
			if scenario == "permissions" && runtime.GOOS == "windows" {
				t.Skip("Windows uses ACLs")
			}
			c, ca, calls, _ := testClientCredentials(t, time.Now().Add(-time.Hour))
			var setupErr error
			switch scenario {
			case "untrusted":
				setupErr = os.WriteFile(c.CAFile, ssh.MarshalAuthorizedKey(testSigner(t).PublicKey()), 0600)
			case "principal":
				c.Principal = "other"
			case "future":
				signer, _, err := loadSigner(c.KeyFile, c.CertFile)
				if err != nil {
					t.Fatal(err)
				}
				cert := testCertificate(t, signer, ca.signer, "operator", "admin", time.Now().Add(4*time.Minute))
				cert.ValidAfter = uint64(time.Now().Add(time.Minute).Unix())
				if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
					t.Fatal(err)
				}
				setupErr = os.WriteFile(c.CertFile, ssh.MarshalAuthorizedKey(cert), 0600)
			case "token expired":
				ca.user.Refresh[0].Expires = time.Now().Add(-time.Minute)
			case "missing token":
				setupErr = os.Remove(c.RefreshTokenFile)
			case "permissions":
				setupErr = os.Chmod(c.RefreshTokenFile, 0644)
			case "no renewal config":
				c.CAURL = ""
			case "untrusted response":
				ca.signer = testSigner(t)
			}
			if setupErr != nil {
				t.Fatal(setupErr)
			}
			before, _ := os.ReadFile(c.CertFile)
			tokenBefore, _ := os.ReadFile(c.RefreshTokenFile)
			_, _, err := c.clientSigner(context.Background())
			if err == nil {
				t.Fatal("invalid renewal succeeded")
			}
			after, _ := os.ReadFile(c.CertFile)
			tokenAfter, _ := os.ReadFile(c.RefreshTokenFile)
			if !bytes.Equal(before, after) || !bytes.Equal(tokenBefore, tokenAfter) {
				t.Fatal("rejected renewal replaced credentials")
			}
			want := int32(0)
			if scenario == "token expired" || scenario == "untrusted response" {
				want = 1
			}
			if calls.Load() != want {
				t.Fatalf("unexpected CA call count: %d", calls.Load())
			}
			if scenario == "token expired" && !strings.Contains(err.Error(), "portal cert request") {
				t.Fatalf("missing recovery instruction: %v", err)
			}
		})
	}
}

func TestClientRefreshConcurrentAndManualRecovery(t *testing.T) {
	c, _, calls, _ := testClientCredentials(t, time.Now().Add(-time.Hour))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, _, err := c.clientSigner(context.Background()); err != nil {
				t.Errorf("concurrent renewal: %v", err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("token consumed %d times", calls.Load())
	}
	// Explicit refresh does not depend on the old certificate being present.
	if err := os.Remove(c.CertFile); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("manual refresh did not share persisted token")
	}
}

func TestClientAutoRefreshBeforeLookup(t *testing.T) {
	c, ca, calls, _ := testClientCredentials(t, time.Now().Add(-time.Hour))
	_, err := c.Query(context.Background(), MonitorRequest{Source: "memory", Mode: "snapshot"})
	if err == nil || calls.Load() != 1 {
		t.Fatalf("query did not refresh before lookup: %v", err)
	}
	_, cert, err := loadSigner(c.KeyFile, c.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyUserCertificate(ca.signer.PublicKey(), "admin", cert); err != nil {
		t.Fatal(err)
	}
}

func TestClientRefreshProcesses(t *testing.T) {
	if os.Getenv("PORTAL_TEST_REFRESH_HELPER") == "1" {
		roots := x509.NewCertPool()
		data, err := os.ReadFile(os.Args[len(os.Args)-1])
		if err != nil || !roots.AppendCertsFromPEM(data) {
			t.Fatal("invalid test TLS CA")
		}
		http.DefaultClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
		c, err := (Client{ConfigFile: os.Args[len(os.Args)-2]}).configured()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.clientSigner(context.Background()); err != nil {
			t.Fatal(err)
		}
		return
	}
	c, _, calls, server := testClientCredentials(t, time.Now().Add(-time.Hour))
	tlsPath := filepath.Join(t.TempDir(), "tls-ca.pem")
	if err := os.WriteFile(tlsPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0644); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			cmd := exec.Command(binary, "-test.run=^TestClientRefreshProcesses$", "--", c.ConfigFile, tlsPath)
			cmd.Env = append(os.Environ(), "PORTAL_TEST_REFRESH_HELPER=1")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("refresh helper: %v: %s", err, output)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("cross-process renewal consumed token %d times", calls.Load())
	}
	lock, err := lockCredentials(context.Background(), c.RefreshTokenFile)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lockCredentials(ctx, c.RefreshTokenFile); !errors.Is(err, context.Canceled) {
		t.Fatalf("lock wait ignored cancellation: %v", err)
	}
}

func TestRefreshNeverForwardsTokenOnRedirect(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	previous := http.DefaultClient
	http.DefaultClient = source.Client()
	defer func() { http.DefaultClient = previous }()
	_, err := RefreshCertificate(context.Background(), source.URL, testSigner(t), "0123456789abcdefghijklmnopqrstuv")
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") || forwarded.Load() != 0 {
		t.Fatalf("refresh token followed redirect: %v, forwarded=%d", err, forwarded.Load())
	}
}
