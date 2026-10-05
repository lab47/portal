package portal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/ssh"
)

type caUser struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	Credentials []webauthn.Credential `json:"credentials"`
	Refresh     []caRefresh           `json:"refresh,omitempty"`
}

type caRefresh struct {
	Hash    [32]byte  `json:"hash"`
	KeyHash [32]byte  `json:"key_hash"`
	Expires time.Time `json:"expires"`
}

const refreshProofDomain = "portal-cert-refresh-v1\x00"

func refreshProof(token string) []byte { return []byte(refreshProofDomain + token) }

func (u *caUser) WebAuthnID() []byte                         { return u.ID }
func (u *caUser) WebAuthnName() string                       { return u.Name }
func (u *caUser) WebAuthnDisplayName() string                { return u.Name }
func (u *caUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type caRequest struct {
	key     ssh.PublicKey
	expires time.Time
	session *webauthn.SessionData
	enroll  bool
	cert    []byte
	refresh string
}

// CA serves a passkey-gated SSH user certificate signer. Its private key and
// persistent credential state must live outside the public coordinator.
type CA struct {
	mu          sync.Mutex
	wa          *webauthn.WebAuthn
	signer      ssh.Signer
	statePath   string
	user        caUser
	principal   string
	enrollToken [32]byte
	requests    map[string]*caRequest
}

// NewCA loads the signing key and passkey state. The enrollment token is an
// administrator-provided one-time secret; omit it after enrollment is complete.
func NewCA(origin, identity, principal, keyPath, statePath, enrollmentToken string) (*CA, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || identity == "" || principal == "" || keyPath == "" || statePath == "" {
		return nil, errors.New("CA requires HTTPS origin, identity, principal, signing key and state path")
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Portal CA", RPID: u.Hostname(), RPOrigins: []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired},
	})
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil || keyInfo.Mode().Perm()&0077 != 0 {
		return nil, errors.New("CA signing key must only be readable by its owner")
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}
	c := &CA{wa: wa, signer: signer, statePath: statePath, principal: principal, requests: make(map[string]*caRequest)}
	c.enrollToken = sha256.Sum256([]byte(enrollmentToken))
	data, err = os.ReadFile(statePath)
	if err == nil {
		info, err := os.Stat(statePath)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("CA state must only be readable by its owner")
		}
		if err = json.Unmarshal(data, &c.user); err != nil {
			return nil, err
		}
		if c.user.Name != identity || len(c.user.ID) != 32 {
			return nil, errors.New("CA state identity mismatch")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if len(enrollmentToken) < 32 {
			return nil, errors.New("initial enrollment requires a token of at least 32 characters")
		}
		c.user = caUser{ID: make([]byte, 32), Name: identity}
		if _, err = rand.Read(c.user.ID); err != nil {
			return nil, err
		}
		if err = c.save(); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	if len(c.user.Credentials) == 0 && len(enrollmentToken) < 32 {
		return nil, errors.New("initial enrollment requires a token of at least 32 characters")
	}
	return c, nil
}

func (c *CA) save() error {
	data, err := json.Marshal(c.user)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(c.statePath), ".portal-ca-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), c.statePath)
}

func randomID() (string, error) {
	var id [24]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(id[:]), nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(value)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}

// Handler exposes device requests and one-time browser passkey ceremonies.
func (c *CA) Handler(origin string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ca.pub", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(ssh.MarshalAuthorizedKey(c.signer.PublicKey()))
	})
	mux.HandleFunc("POST /requests", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			PublicKey string `json:"public_key"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(input.PublicKey))
		if err != nil || len(rest) != 0 || len(input.PublicKey) > 4096 {
			http.Error(w, "invalid SSH public key", http.StatusBadRequest)
			return
		}
		if _, ok := key.(*ssh.Certificate); ok {
			http.Error(w, "certificate is not a public key", http.StatusBadRequest)
			return
		}
		id, err := randomID()
		if err != nil {
			http.Error(w, "random source failed", http.StatusInternalServerError)
			return
		}
		code, err := randomID()
		if err != nil {
			http.Error(w, "random source failed", http.StatusInternalServerError)
			return
		}
		c.mu.Lock()
		for k, v := range c.requests {
			if time.Now().After(v.expires) {
				delete(c.requests, k)
			}
		}
		if len(c.requests) >= 200 {
			c.mu.Unlock()
			http.Error(w, "too many pending requests", http.StatusTooManyRequests)
			return
		}
		c.requests[code] = &caRequest{key: key, expires: time.Now().Add(5 * time.Minute)}
		c.requests[id] = c.requests[code]
		c.mu.Unlock()
		writeJSON(w, map[string]string{"id": id, "url": origin + "/approve?code=" + code})
	})
	mux.HandleFunc("GET /requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		request := c.requests[r.PathValue("id")]
		if request == nil || time.Now().After(request.expires) {
			http.NotFound(w, r)
			return
		}
		if request.cert == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeJSON(w, map[string]string{"certificate": string(request.cert), "refresh_token": request.refresh})
		delete(c.requests, r.PathValue("id"))
	})
	mux.HandleFunc("POST /refresh", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Token     string `json:"token"`
			PublicKey string `json:"public_key"`
			Signature []byte `json:"signature"`
		}
		if !decodeJSON(w, r, &input) {
			return
		}
		key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(input.PublicKey))
		if err != nil || len(rest) != 0 || len(input.PublicKey) > 4096 || len(input.Token) != 32 {
			http.Error(w, "invalid refresh request", http.StatusBadRequest)
			return
		}
		if _, ok := key.(*ssh.Certificate); ok {
			http.Error(w, "invalid refresh request", http.StatusBadRequest)
			return
		}
		var sig ssh.Signature
		if err := ssh.Unmarshal(input.Signature, &sig); err != nil || key.Verify(refreshProof(input.Token), &sig) != nil {
			http.Error(w, "invalid key proof", http.StatusForbidden)
			return
		}
		hash := sha256.Sum256([]byte(input.Token))
		keyHash := sha256.Sum256(key.Marshal())
		c.mu.Lock()
		defer c.mu.Unlock()
		for i, credential := range c.user.Refresh {
			if credential.Hash != hash {
				continue
			}
			if time.Now().After(credential.Expires) || credential.KeyHash != keyHash {
				http.Error(w, "invalid or expired refresh token", http.StatusForbidden)
				return
			}
			next, err := randomID()
			if err != nil {
				http.Error(w, "random source failed", http.StatusInternalServerError)
				return
			}
			cert, err := c.signCertificate(key)
			if err != nil {
				http.Error(w, "signing failed", http.StatusInternalServerError)
				return
			}
			c.user.Refresh[i].Hash = sha256.Sum256([]byte(next))
			if err := c.save(); err != nil {
				c.user.Refresh[i] = credential
				log.Printf("CA state save failed: %v", err)
				http.Error(w, "CA state unavailable", http.StatusInternalServerError)
				return
			}
			log.Printf("refreshed SSH certificate for %s", c.user.Name)
			writeJSON(w, map[string]string{"certificate": string(cert), "refresh_token": next})
			return
		}
		http.Error(w, "invalid or expired refresh token", http.StatusForbidden)
	})
	mux.HandleFunc("GET /approve", func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		request := c.requests[r.URL.Query().Get("code")]
		valid := request != nil && time.Now().Before(request.expires) && request.cert == nil
		var fingerprint string
		if valid {
			fingerprint = ssh.FingerprintSHA256(request.key)
		}
		c.mu.Unlock()
		if !valid {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(strings.ReplaceAll(approvalPage, "FINGERPRINT", fingerprint)))
	})
	mux.HandleFunc("POST /ceremony/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != origin {
			http.Error(w, "invalid origin", http.StatusForbidden)
			return
		}
		var input struct{ Code, Token string }
		if !decodeJSON(w, r, &input) {
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		request := c.requests[input.Code]
		if request == nil || time.Now().After(request.expires) || request.cert != nil || request.session != nil {
			http.Error(w, "invalid or expired request", http.StatusBadRequest)
			return
		}
		if len(c.user.Credentials) == 0 {
			hash := sha256.Sum256([]byte(input.Token))
			if len(input.Token) < 32 || subtle.ConstantTimeCompare(hash[:], c.enrollToken[:]) != 1 {
				http.Error(w, "invalid enrollment token", http.StatusForbidden)
				return
			}
			options, session, err := c.wa.BeginRegistration(&c.user)
			if err != nil {
				http.Error(w, "registration failed", http.StatusInternalServerError)
				return
			}
			request.session, request.enroll = session, true
			writeJSON(w, map[string]any{"kind": "register", "options": options})
		} else {
			options, session, err := c.wa.BeginLogin(&c.user, webauthn.WithUserVerification(protocol.VerificationRequired))
			if err != nil {
				http.Error(w, "login failed", http.StatusInternalServerError)
				return
			}
			request.session = session
			writeJSON(w, map[string]any{"kind": "login", "options": options})
		}
	})
	mux.HandleFunc("POST /ceremony/finish", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != origin {
			http.Error(w, "invalid origin", http.StatusForbidden)
			return
		}
		code := r.URL.Query().Get("code")
		c.mu.Lock()
		defer c.mu.Unlock()
		request := c.requests[code]
		if request == nil || time.Now().After(request.expires) || request.session == nil || request.cert != nil {
			http.Error(w, "invalid or expired request", http.StatusBadRequest)
			return
		}
		session := *request.session
		request.session = nil // Consume the challenge even if verification fails.
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		previous := append([]webauthn.Credential(nil), c.user.Credentials...)
		if request.enroll {
			if len(c.user.Credentials) != 0 {
				http.Error(w, "already enrolled", http.StatusConflict)
				return
			}
			credential, err := c.wa.FinishRegistration(&c.user, session, r)
			if err != nil {
				http.Error(w, "passkey verification failed", http.StatusForbidden)
				return
			}
			c.user.Credentials = append(c.user.Credentials, *credential)
		} else {
			credential, err := c.wa.FinishLogin(&c.user, session, r)
			if err != nil {
				http.Error(w, "passkey verification failed", http.StatusForbidden)
				return
			}
			found := false
			for i := range c.user.Credentials {
				if bytes.Equal(c.user.Credentials[i].ID, credential.ID) {
					c.user.Credentials[i] = *credential
					found = true
				}
			}
			if !found {
				http.Error(w, "credential not enrolled", http.StatusForbidden)
				return
			}
		}
		certData, err := c.signCertificate(request.key)
		if err != nil {
			c.user.Credentials = previous
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		refresh, err := randomID()
		if err != nil {
			c.user.Credentials = previous
			http.Error(w, "random source failed", http.StatusInternalServerError)
			return
		}
		oldRefresh := c.user.Refresh
		active := make([]caRefresh, 0, len(oldRefresh)+1)
		for _, entry := range oldRefresh {
			if time.Now().Before(entry.Expires) {
				active = append(active, entry)
			}
		}
		if len(active) >= 64 {
			c.user.Credentials = previous
			http.Error(w, "too many active devices", http.StatusTooManyRequests)
			return
		}
		active = append(active, caRefresh{Hash: sha256.Sum256([]byte(refresh)),
			KeyHash: sha256.Sum256(request.key.Marshal()), Expires: time.Now().Add(30 * 24 * time.Hour)})
		c.user.Refresh = active
		if err := c.save(); err != nil {
			c.user.Credentials = previous
			c.user.Refresh = oldRefresh
			log.Printf("CA state save failed: %v", err)
			http.Error(w, "CA state unavailable", http.StatusInternalServerError)
			return
		}
		request.cert = certData
		request.refresh = refresh
		delete(c.requests, code)
		log.Printf("issued SSH certificate for %s", c.user.Name)
		w.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
		mux.ServeHTTP(w, r)
	})
}

func (c *CA) signCertificate(key ssh.PublicKey) ([]byte, error) {
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return nil, err
	}
	now := time.Now()
	cert := &ssh.Certificate{Key: key, Serial: binary.BigEndian.Uint64(serial[:]), CertType: ssh.UserCert,
		KeyId: c.user.Name, ValidPrincipals: []string{c.principal},
		ValidAfter: uint64(now.Add(-time.Minute).Unix()), ValidBefore: uint64(now.Add(48 * time.Hour).Unix())}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}

// IssuedCertificate contains a certificate and the next key-bound refresh token.
// Keep RefreshToken private; the CA stores only its hash.
type IssuedCertificate struct {
	Certificate  []byte
	RefreshToken string
}

func caOrigin(caURL string) (string, error) {
	base := strings.TrimRight(caURL, "/")
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("CA URL must be an HTTPS origin")
	}
	return base, nil
}

func parseIssued(data io.Reader, pub ssh.PublicKey) (IssuedCertificate, error) {
	var result struct {
		Certificate  string `json:"certificate"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(io.LimitReader(data, 8192)).Decode(&result); err != nil {
		return IssuedCertificate{}, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(result.Certificate))
	cert, ok := key.(*ssh.Certificate)
	if err != nil || !ok || !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) || len(result.RefreshToken) != 32 {
		return IssuedCertificate{}, errors.New("CA returned invalid certificate or refresh token")
	}
	return IssuedCertificate{Certificate: []byte(result.Certificate), RefreshToken: result.RefreshToken}, nil
}

// RequestCertificate creates a signing request and waits for browser approval.
func RequestCertificate(ctx context.Context, caURL string, pub ssh.PublicKey, notify func(string)) (IssuedCertificate, error) {
	base, err := caOrigin(caURL)
	if err != nil {
		return IssuedCertificate{}, err
	}
	data, _ := json.Marshal(map[string]string{"public_key": string(ssh.MarshalAuthorizedKey(pub))})
	create, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/requests", bytes.NewReader(data))
	if err != nil {
		return IssuedCertificate{}, err
	}
	create.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(create)
	if err != nil {
		return IssuedCertificate{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return IssuedCertificate{}, fmt.Errorf("CA request: HTTP %d", response.StatusCode)
	}
	var pending struct{ ID, URL string }
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&pending); err != nil {
		return IssuedCertificate{}, err
	}
	if pending.ID == "" || !strings.HasPrefix(pending.URL, base+"/approve?") {
		return IssuedCertificate{}, errors.New("invalid CA response")
	}
	notify(pending.URL)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return IssuedCertificate{}, ctx.Err()
		case <-ticker.C:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/requests/"+pending.ID, nil)
		if err != nil {
			return IssuedCertificate{}, err
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return IssuedCertificate{}, err
		}
		if res.StatusCode == http.StatusAccepted {
			res.Body.Close()
			continue
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			return IssuedCertificate{}, fmt.Errorf("CA poll: HTTP %d", res.StatusCode)
		}
		result, err := parseIssued(res.Body, pub)
		res.Body.Close()
		return result, err
	}
}

// RefreshCertificate rotates a token and issues another certificate for the
// same SSH key without a browser interaction. The previous token is consumed.
func RefreshCertificate(ctx context.Context, caURL string, signer ssh.Signer, token string) (IssuedCertificate, error) {
	base, err := caOrigin(caURL)
	if err != nil {
		return IssuedCertificate{}, err
	}
	if len(token) != 32 {
		return IssuedCertificate{}, errors.New("invalid refresh token")
	}
	sig, err := signer.Sign(rand.Reader, refreshProof(token))
	if err != nil {
		return IssuedCertificate{}, err
	}
	data, _ := json.Marshal(map[string]any{"token": token, "public_key": string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "signature": ssh.Marshal(sig)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/refresh", bytes.NewReader(data))
	if err != nil {
		return IssuedCertificate{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := *http.DefaultClient
	// A renewal carries a private token; never forward it to a redirect target.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return IssuedCertificate{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return IssuedCertificate{}, fmt.Errorf("CA refresh: HTTP %d", res.StatusCode)
	}
	return parseIssued(res.Body, signer.PublicKey())
}
