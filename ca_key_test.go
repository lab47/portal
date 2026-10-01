package portal

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestCAPublicKeyEndpointAndURLLoading(t *testing.T) {
	ca, _, privatePath := testCA(t)
	expected := ssh.MarshalAuthorizedKey(ca.signer.PublicKey())
	w := httptest.NewRecorder()
	ca.Handler("https://ca.example.com").ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ca.pub", nil))
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), expected) || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatal("public key endpoint did not return the signing key's public counterpart")
	}
	private, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	certificate := testCertificate(t, testSigner(t), ca.signer, "operator", "admin", time.Now().Add(time.Hour))
	plainHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(expected) // A downgrade would otherwise return a valid key.
	}))
	defer plainHTTP.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ca.pub":
			ca.Handler("https://ca.example.com").ServeHTTP(w, r)
		case "/private":
			w.Write(private)
		case "/certificate":
			w.Write(ssh.MarshalAuthorizedKey(certificate))
		case "/multiple":
			w.Write(append(append([]byte{}, expected...), expected...))
		case "/oversized":
			w.Write([]byte(strings.Repeat(" ", 65537)))
		case "/downgrade":
			http.Redirect(w, r, plainHTTP.URL+"/ca.pub", http.StatusFound)
		case "/redirect":
			http.Redirect(w, r, "/ca.pub", http.StatusFound)
		case "/status":
			w.WriteHeader(http.StatusForbidden)
			w.Write(expected)
		default:
			w.Write([]byte("<html>not a key</html>"))
		}
	}))
	defer server.Close()
	if _, err := LoadCAPublicKey(t.Context(), server.URL+"/ca.pub"); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	previous := http.DefaultClient
	http.DefaultClient = server.Client() // Trust only the test server's TLS certificate.
	t.Cleanup(func() { http.DefaultClient = previous })
	for _, path := range []string{"/ca.pub", "/redirect"} {
		key, err := LoadCAPublicKey(t.Context(), server.URL+path)
		if err != nil || !bytes.Equal(key.Marshal(), ca.signer.PublicKey().Marshal()) {
			t.Fatalf("wrong key fetched: %v", err)
		}
		if err := VerifyUserCertificate(key, "admin", certificate); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/private", "/certificate", "/multiple", "/oversized", "/downgrade", "/status", "/html"} {
		if _, err := LoadCAPublicKey(t.Context(), server.URL+path); err == nil {
			t.Fatalf("invalid public key response accepted at %s", path)
		}
	}
	for _, source := range []string{plainHTTP.URL + "/ca.pub", "ftp://ca.example/ca.pub", server.URL + "/ca.pub?token=secret", server.URL + "/ca.pub#fragment", "https://user:secret@" + strings.TrimPrefix(server.URL, "https://") + "/ca.pub", privatePath} {
		if _, err := LoadCAPublicKey(t.Context(), source); err == nil {
			t.Fatal("insecure URL or private key accepted as CA")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := LoadCAPublicKey(ctx, server.URL+"/ca.pub"); !errors.Is(err, context.Canceled) {
		t.Fatalf("fetch ignored context cancellation: %v", err)
	}
}
