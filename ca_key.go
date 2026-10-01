package portal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// LoadCAPublicKey reads a plain SSH public key from a local file or HTTPS URL.
// URL trust comes from TLS; server initialization pins the fetched key inline.
func LoadCAPublicKey(ctx context.Context, source string) (ssh.PublicKey, error) {
	var reader io.ReadCloser
	if strings.Contains(source, "://") {
		u, err := url.Parse(source)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("CA public key URL must use HTTPS without credentials, query or fragment")
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}
		client := *http.DefaultClient
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.RawQuery != "" || req.URL.Fragment != "" {
				return errors.New("CA public key redirect must stay on HTTPS without credentials, query or fragment")
			}
			return nil
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch CA public key: %w", err)
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			return nil, fmt.Errorf("fetch CA public key: HTTP %d", res.StatusCode)
		}
		reader = res.Body
	} else {
		f, err := os.Open(source)
		if err != nil {
			return nil, err
		}
		reader = f
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, 64*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64*1024 {
		return nil, errors.New("CA public key exceeds 64 KiB")
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("CA must contain exactly one SSH public key")
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return nil, errors.New("CA must be a plain SSH public key, not a certificate")
	}
	return key, nil
}
