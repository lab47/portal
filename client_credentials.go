package portal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"golang.org/x/crypto/ssh"
)

const certificateRenewBefore = 5 * time.Minute

func certificateNeedsRefresh(cert *ssh.Certificate) bool {
	return cert.ValidBefore != ssh.CertTimeInfinity && cert.ValidBefore <= uint64(time.Now().Add(certificateRenewBefore).Unix())
}

func (c Client) clientSigner(ctx context.Context) (ssh.Signer, *ssh.Certificate, error) {
	signer, cert, err := loadSigner(c.KeyFile, c.CertFile)
	if err != nil {
		return nil, nil, err
	}
	if certificateNeedsRefresh(cert) && c.CAURL != "" && c.CAFile != "" {
		return c.refreshSigner(ctx, false)
	}
	if c.CAFile != "" {
		ca, loadErr := LoadCAPublicKey(ctx, c.CAFile)
		if loadErr != nil {
			return nil, nil, loadErr
		}
		err = VerifyUserCertificate(ca, c.Principal, cert)
	} else {
		err = (&ssh.CertChecker{}).CheckCert(c.Principal, cert)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("client certificate: %w (configure ca_url and ca for automatic renewal, or run portal cert request)", err)
	}
	return signer, cert, nil
}

// Refresh explicitly renews a certificate, even if it is still valid or missing.
// It uses the same credential lock and persistence as automatic renewal.
func (c Client) Refresh(ctx context.Context) (*ssh.Certificate, error) {
	c, err := c.configured()
	if err != nil {
		return nil, err
	}
	_, cert, err := c.refreshSigner(ctx, true)
	return cert, err
}

func (c Client) refreshSigner(ctx context.Context, force bool) (ssh.Signer, *ssh.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if c.CAURL == "" || c.CAFile == "" || c.KeyFile == "" || c.CertFile == "" || c.RefreshTokenFile == "" {
		return nil, nil, errors.New("certificate renewal requires CA URL, trusted CA, key, certificate and refresh token paths")
	}
	if err := credentialPaths(c.KeyFile, c.CertFile, c.RefreshTokenFile, c.CAFile); err != nil {
		return nil, nil, err
	}
	lock, err := lockCredentials(ctx, c.RefreshTokenFile)
	if err != nil {
		return nil, nil, err
	}
	defer lock.Close()
	ca, err := LoadCAPublicKey(ctx, c.CAFile)
	if err != nil {
		return nil, nil, err
	}
	var signer ssh.Signer
	if !force {
		// Another caller may have renewed while we waited for the lock.
		var cert *ssh.Certificate
		signer, cert, err = loadSigner(c.KeyFile, c.CertFile)
		if err != nil {
			return nil, nil, err
		}
		at := time.Now()
		if cert.ValidBefore > 0 && cert.ValidBefore <= uint64(at.Unix()) {
			// Verify signature, CA and principal at the last valid instant; only
			// expiry is allowed to differ during headless recovery.
			at = time.Unix(int64(cert.ValidBefore-1), 0)
		}
		if err := verifyUserCertificateAt(ca, c.Principal, cert, at); err != nil {
			return nil, nil, err
		}
		if !certificateNeedsRefresh(cert) {
			return signer, cert, nil
		}
	} else {
		private, err := os.ReadFile(c.KeyFile)
		if err != nil {
			return nil, nil, err
		}
		signer, err = ssh.ParsePrivateKey(private)
		if err != nil {
			return nil, nil, err
		}
	}
	info, err := os.Stat(c.RefreshTokenFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read refresh token: %w; run portal cert request to obtain credentials", err)
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, nil, errors.New("refresh token file must be a regular file readable only by its owner")
	}
	token, err := os.ReadFile(c.RefreshTokenFile)
	if err != nil {
		return nil, nil, err
	}
	issued, err := RefreshCertificate(ctx, c.CAURL, signer, strings.TrimSpace(string(token)))
	if err != nil {
		return nil, nil, fmt.Errorf("certificate renewal failed: %w; if the refresh token expired, run portal cert request", err)
	}
	cert, err := saveIssuedCertificate(issued, signer, ca, c.Principal, c.CertFile, c.RefreshTokenFile)
	return signer, cert, err
}

// SaveIssuedCertificate verifies and persists an approved certificate and its
// rotated token. The private token is saved first so a certificate-write failure
// can be recovered by another refresh. No credential contents are logged.
func SaveIssuedCertificate(ctx context.Context, issued IssuedCertificate, signer ssh.Signer, caPath, principal, keyPath, certPath, tokenPath string) (*ssh.Certificate, error) {
	if tokenPath == "" {
		tokenPath = keyPath + ".refresh"
	}
	if err := credentialPaths(keyPath, certPath, tokenPath, caPath); err != nil {
		return nil, err
	}
	ca, err := LoadCAPublicKey(ctx, caPath)
	if err != nil {
		return nil, err
	}
	lock, err := lockCredentials(ctx, tokenPath)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	return saveIssuedCertificate(issued, signer, ca, principal, certPath, tokenPath)
}

func saveIssuedCertificate(issued IssuedCertificate, signer ssh.Signer, ca ssh.PublicKey, principal, certPath, tokenPath string) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(issued.Certificate)
	cert, ok := pub.(*ssh.Certificate)
	if err != nil || !ok || !bytes.Equal(cert.Key.Marshal(), signer.PublicKey().Marshal()) {
		return nil, errors.New("CA returned certificate for another SSH key")
	}
	if err := VerifyUserCertificate(ca, principal, cert); err != nil {
		return nil, err
	}
	if len(issued.RefreshToken) != 32 {
		return nil, errors.New("CA returned invalid refresh token")
	}
	if err := writeCredentialAtomic(tokenPath, []byte(issued.RefreshToken), 0600); err != nil {
		return nil, err
	}
	if err := writeCredentialAtomic(certPath, issued.Certificate, 0644); err != nil {
		return nil, err
	}
	return cert, nil
}

func credentialPaths(paths ...string) error {
	seen := make(map[string]bool)
	for _, path := range paths {
		if strings.Contains(path, "://") {
			continue // The trusted CA may be an HTTPS URL.
		}
		if path == "" {
			return errors.New("key, CA, certificate and refresh token paths are required")
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if seen[absolute] {
			return errors.New("key, CA, certificate and refresh token paths must differ")
		}
		seen[absolute] = true
	}
	return nil
}

func lockCredentials(ctx context.Context, tokenPath string) (*flock.Flock, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	lock := flock.New(tokenPath+".lock", flock.SetPermissions(0600))
	locked, err := lock.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil || !locked {
		lock.Close()
		if err == nil {
			err = ctx.Err()
		}
		return nil, fmt.Errorf("lock client credentials: %w", err)
	}
	return lock, nil
}

func writeCredentialAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".portal-credential-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
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
	return os.Rename(f.Name(), path)
}
