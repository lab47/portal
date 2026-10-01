package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lab47/portal"
	"golang.org/x/crypto/ssh"
	"miren.dev/mflags"
)

func registerCACommands(dispatcher *mflags.Dispatcher, ctx context.Context) {
	serve := mflags.NewFlagSet("ca serve")
	listen := serve.String("listen", 0, "127.0.0.1:8081", "HTTP listen address; put behind HTTPS at the configured origin")
	origin := serve.String("origin", 0, "", "public HTTPS origin (WebAuthn relying party)")
	identity := serve.String("identity", 0, "", "fixed certificate identity / server policy key ID")
	principal := serve.String("principal", 0, "admin", "SSH certificate principal")
	caKey := serve.String("ca-key", 0, "", "CA private key file")
	state := serve.String("state", 0, "", "persistent passkey credential state file")
	dispatcher.Dispatch("ca serve", mflags.NewCommand(serve, func(_ *mflags.FlagSet, _ []string) error {
		ca, err := portal.NewCA(*origin, *identity, *principal, *caKey, *state, os.Getenv("PORTAL_CA_ENROLL_TOKEN"))
		if err != nil {
			return err
		}
		srv := &http.Server{Addr: *listen, Handler: ca.Handler(*origin), ReadHeaderTimeout: 5 * time.Second}
		go func() { <-ctx.Done(); srv.Shutdown(context.Background()) }()
		log.Printf("CA listening on %s for %s", *listen, *origin)
		err = srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}, mflags.WithUsage("Serve passkey-backed SSH CA (separate from inventory coordinator)")))

	request := mflags.NewFlagSet("cert request")
	requestConfig := request.String("config", 0, "", "client config file (default: user config directory/portal/config.json)")
	caURL := request.String("ca-url", 0, "", "CA HTTPS origin")
	keyPath := request.String("key", 0, "", "local SSH private key (created if absent)")
	certPath := request.String("cert", 0, "", "output SSH certificate (renewals replace this file)")
	refreshPath := request.String("refresh-token", 0, "", "refresh token file (default: <key>.refresh)")
	trustedCA := request.String("ca", 0, "", "trusted CA public key file or HTTPS URL")
	certPrincipal := request.String("principal", 0, "admin", "expected SSH principal")
	dispatcher.Dispatch("cert request", mflags.NewCommand(request, func(_ *mflags.FlagSet, _ []string) error {
		if err := certificateConfigDefaults(request, *requestConfig, map[string]*string{"key": keyPath, "cert": certPath, "ca": trustedCA, "ca-url": caURL, "principal": certPrincipal}); err != nil {
			return err
		}
		if *caURL == "" || *keyPath == "" || *certPath == "" || *trustedCA == "" {
			return errors.New("--ca-url, --key, --cert and --ca are required")
		}
		if _, err := os.Stat(*keyPath); errors.Is(err, os.ErrNotExist) {
			if err := generateKey(*keyPath); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		keyData, err := os.ReadFile(*keyPath)
		if err != nil {
			return err
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return err
		}
		fmt.Printf("SSH key fingerprint: %s\n", ssh.FingerprintSHA256(signer.PublicKey()))
		wait, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		issued, err := portal.RequestCertificate(wait, *caURL, signer.PublicKey(), func(url string) {
			fmt.Printf("Approve this request in your browser: %s\n", url)
		})
		if err != nil {
			return err
		}
		return saveIssued(issued, signer, *trustedCA, *certPrincipal, *keyPath, *certPath, *refreshPath)
	}, mflags.WithUsage("Generate a local SSH key and request a passkey-approved certificate")))

	refresh := mflags.NewFlagSet("cert refresh")
	refreshConfig := refresh.String("config", 0, "", "client config file (default: user config directory/portal/config.json)")
	refreshURL := refresh.String("ca-url", 0, "", "CA HTTPS origin")
	refreshKey := refresh.String("key", 0, "", "local SSH private key")
	refreshCert := refresh.String("cert", 0, "", "SSH certificate output")
	refreshToken := refresh.String("refresh-token", 0, "", "refresh token file (default: <key>.refresh)")
	refreshCA := refresh.String("ca", 0, "", "trusted CA public key file or HTTPS URL")
	refreshPrincipal := refresh.String("principal", 0, "admin", "expected SSH principal")
	dispatcher.Dispatch("cert refresh", mflags.NewCommand(refresh, func(_ *mflags.FlagSet, _ []string) error {
		if err := certificateConfigDefaults(refresh, *refreshConfig, map[string]*string{"key": refreshKey, "cert": refreshCert, "ca": refreshCA, "ca-url": refreshURL, "principal": refreshPrincipal}); err != nil {
			return err
		}
		if *refreshURL == "" || *refreshKey == "" || *refreshCert == "" || *refreshCA == "" {
			return errors.New("--ca-url, --key, --cert and --ca are required")
		}
		path := *refreshToken
		if path == "" {
			path = *refreshKey + ".refresh"
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0077 != 0 {
			return errors.New("refresh token file must only be readable by its owner")
		}
		token, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		private, err := os.ReadFile(*refreshKey)
		if err != nil {
			return err
		}
		signer, err := ssh.ParsePrivateKey(private)
		if err != nil {
			return err
		}
		issued, err := portal.RefreshCertificate(ctx, *refreshURL, signer, strings.TrimSpace(string(token)))
		if err != nil {
			return err
		}
		return saveIssued(issued, signer, *refreshCA, *refreshPrincipal, *refreshKey, *refreshCert, path)
	}, mflags.WithUsage("Rotate a key-bound refresh token and renew a certificate without a browser")))
}

func saveIssued(issued portal.IssuedCertificate, signer ssh.Signer, caPath, principal, keyPath, certPath, tokenPath string) error {
	if tokenPath == "" {
		tokenPath = keyPath + ".refresh"
	}
	if tokenPath == keyPath || tokenPath == certPath || certPath == keyPath || caPath == tokenPath || caPath == certPath {
		return errors.New("key, CA, certificate and refresh token paths must differ")
	}
	caPub, err := portal.LoadCAPublicKey(context.Background(), caPath)
	if err != nil {
		return err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(issued.Certificate)
	cert, ok := pub.(*ssh.Certificate)
	if err != nil || !ok || !bytes.Equal(cert.Key.Marshal(), signer.PublicKey().Marshal()) {
		return errors.New("CA returned certificate for another SSH key")
	}
	if err := portal.VerifyUserCertificate(caPub, principal, cert); err != nil {
		return err
	}
	if len(issued.RefreshToken) != 32 {
		return errors.New("CA returned invalid refresh token")
	}
	if err := writeAtomic(tokenPath, []byte(issued.RefreshToken), 0600); err != nil {
		return err
	}
	if err := writeAtomic(certPath, issued.Certificate, 0644); err != nil {
		return err
	}
	fmt.Printf("Certificate for %s written to %s (expires %s); refresh token saved to %s\n", cert.KeyId, certPath, time.Unix(int64(cert.ValidBefore), 0).Format(time.RFC3339), tokenPath)
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
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
