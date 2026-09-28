package portal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testCA(t *testing.T) (*CA, ssh.PublicKey, string) {
	t.Helper()
	dir := t.TempDir()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "ca")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state")
	ca, err := NewCA("https://ca.example.com", "operator", "admin", keyPath, statePath, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	_, userKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(userKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	return ca, pub, keyPath
}

func TestCARequestRequiresPasskeyAndBindsChallenge(t *testing.T) {
	ca, pub, _ := testCA(t)
	handler := ca.Handler("https://ca.example.com")
	post := func(path, origin string, data any) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(data)
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	created := post("/requests", "", map[string]string{"public_key": string(ssh.MarshalAuthorizedKey(pub))})
	if created.Code != http.StatusOK {
		t.Fatal(created.Body)
	}
	var pending struct{ ID, URL string }
	if err := json.Unmarshal(created.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(pending.URL)
	if err != nil {
		t.Fatal(err)
	}
	code := u.Query().Get("code")
	if code == "" || pending.ID == code {
		t.Fatal("approval code must differ from polling secret")
	}
	poll := func() int {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/requests/"+pending.ID, nil))
		return w.Code
	}
	if poll() != http.StatusAccepted {
		t.Fatal("certificate was available before passkey approval")
	}
	if got := post("/ceremony/start", "https://evil.example.com", map[string]string{"code": code, "token": "0123456789abcdef0123456789abcdef"}).Code; got != http.StatusForbidden {
		t.Fatalf("cross-origin ceremony: %d", got)
	}
	if got := post("/ceremony/start", "https://ca.example.com", map[string]string{"code": code, "token": "wrong"}).Code; got != http.StatusForbidden {
		t.Fatalf("incorrect enrollment token: %d", got)
	}
	started := post("/ceremony/start", "https://ca.example.com", map[string]string{"code": code, "token": "0123456789abcdef0123456789abcdef"})
	if started.Code != http.StatusOK || !strings.Contains(started.Body.String(), `"kind":"register"`) {
		t.Fatalf("registration start: %d %s", started.Code, started.Body.String())
	}
	finish := func() int {
		return post("/ceremony/finish?code="+code, "https://ca.example.com", map[string]string{"bogus": "assertion"}).Code
	}
	if got := finish(); got != http.StatusForbidden {
		t.Fatalf("invalid passkey assertion: %d", got)
	}
	if got := finish(); got != http.StatusBadRequest {
		t.Fatalf("replayed challenge: %d", got)
	}
	if poll() != http.StatusAccepted {
		t.Fatal("certificate issued without valid passkey assertion")
	}
}

func TestCAStateIdentityAndPermissions(t *testing.T) {
	ca, _, keyPath := testCA(t)
	if _, err := NewCA("https://ca.example.com", "operator", "admin", keyPath, ca.statePath, "0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("restart with existing state: %v", err)
	}
	if _, err := NewCA("https://ca.example.com", "another", "admin", keyPath, ca.statePath, "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("different identity accepted existing credential state")
	}
	if err := os.Chmod(ca.statePath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCA("https://ca.example.com", "operator", "admin", keyPath, ca.statePath, "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("world-readable credential state accepted")
	}
}

func TestCACertificateValidFor48Hours(t *testing.T) {
	ca, pub, _ := testCA(t)
	before := time.Now()
	data, err := ca.signCertificate(pub)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	cert, ok := key.(*ssh.Certificate)
	if err != nil || !ok {
		t.Fatalf("issued certificate: %v", err)
	}
	if err := VerifyUserCertificate(ca.signer.PublicKey(), "admin", cert); err != nil {
		t.Fatalf("certificate signature/principal: %v", err)
	}
	if cert.KeyId != "operator" || !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) {
		t.Fatalf("certificate identity or key mismatch: %q", cert.KeyId)
	}
	expires := time.Unix(int64(cert.ValidBefore), 0)
	if expires.Before(before.Add(48*time.Hour-time.Second)) || expires.After(time.Now().Add(48*time.Hour)) {
		t.Fatalf("certificate expires %s, want 48 hours from issuance", expires)
	}
}

func TestCARefreshRotationAndKeyBinding(t *testing.T) {
	ca, _, keyPath := testCA(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ssh.NewSignerFromKey(otherPrivate)
	if err != nil {
		t.Fatal(err)
	}
	token := "0123456789abcdefghijklmnopqrstuv"
	expires := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	ca.user.Refresh = []caRefresh{{Hash: sha256.Sum256([]byte(token)), KeyHash: sha256.Sum256(signer.PublicKey().Marshal()), Expires: expires}}
	if err := ca.save(); err != nil {
		t.Fatal(err)
	}
	post := func(key ssh.PublicKey, signer ssh.Signer, token string) *httptest.ResponseRecorder {
		t.Helper()
		sig, err := signer.Sign(rand.Reader, refreshProof(token))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"public_key": string(ssh.MarshalAuthorizedKey(key)), "token": token, "signature": ssh.Marshal(sig)})
		w := httptest.NewRecorder()
		ca.Handler("https://ca.example.com").ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(body)))
		return w
	}
	if got := post(other.PublicKey(), other, token).Code; got != http.StatusForbidden {
		t.Fatalf("token used for a different key: %d", got)
	}
	if got := post(signer.PublicKey(), other, token).Code; got != http.StatusForbidden {
		t.Fatalf("token without key possession: %d", got)
	}
	valid := post(signer.PublicKey(), signer, token)
	if valid.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", valid.Code, valid.Body)
	}
	var result struct {
		Certificate  string `json:"certificate"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(valid.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(result.Certificate))
	cert, ok := key.(*ssh.Certificate)
	if err != nil || !ok || !bytes.Equal(cert.Key.Marshal(), signer.PublicKey().Marshal()) || VerifyUserCertificate(ca.signer.PublicKey(), "admin", cert) != nil {
		t.Fatal("refresh certificate is invalid or not bound to client key")
	}
	if time.Until(time.Unix(int64(cert.ValidBefore), 0)) < 48*time.Hour-time.Minute {
		t.Fatal("refresh certificate is not valid for 48 hours")
	}
	if result.RefreshToken == token || len(result.RefreshToken) != 32 || ca.user.Refresh[0].Expires != expires {
		t.Fatal("refresh token did not rotate or its 30-day deadline was extended")
	}
	if got := post(signer.PublicKey(), signer, token).Code; got != http.StatusForbidden {
		t.Fatalf("replayed token: %d", got)
	}
	state, err := os.ReadFile(ca.statePath)
	if err != nil || bytes.Contains(state, []byte(result.RefreshToken)) || bytes.Contains(state, []byte(token)) {
		t.Fatal("refresh token stored in plaintext")
	}
	reloaded, err := NewCA("https://ca.example.com", "operator", "admin", keyPath, ca.statePath, "0123456789abcdef0123456789abcdef")
	if err != nil || reloaded.user.Refresh[0].Hash != sha256.Sum256([]byte(result.RefreshToken)) {
		t.Fatalf("rotated token not persisted: %v", err)
	}
	ca.user.Refresh[0].Expires = time.Now().Add(-time.Second)
	if got := post(signer.PublicKey(), signer, result.RefreshToken).Code; got != http.StatusForbidden {
		t.Fatalf("expired token: %d", got)
	}
}
