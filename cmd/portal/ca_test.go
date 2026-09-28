package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lab47/portal"
	"golang.org/x/crypto/ssh"
)

func TestSaveIssuedKeepsRotatedTokenPrivate(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	key := filepath.Join(dir, "client")
	certPath := filepath.Join(dir, "client-cert.pub")
	for _, path := range []string{ca, key} {
		if err := generateKey(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := issueCertificate(ca, key+".pub", "admin", "operator", certPath, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	issued := portal.IssuedCertificate{Certificate: certData, RefreshToken: "0123456789abcdefghijklmnopqrstuv"}
	if err := saveIssued(issued, signer, ca+".pub", "admin", key, certPath, ""); err != nil {
		t.Fatal(err)
	}
	tokenPath := key + ".refresh"
	info, err := os.Stat(tokenPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("refresh token permissions: %v, %v", info, err)
	}
	stored, err := os.ReadFile(tokenPath)
	if err != nil || !bytes.Equal(stored, []byte(issued.RefreshToken)) {
		t.Fatalf("stored refresh token: %v", err)
	}
	issued.RefreshToken = "abcdefghijklmnopqrstuvwxyz012345"
	if err := saveIssued(issued, signer, ca+".pub", "admin", key, certPath, ""); err != nil {
		t.Fatal(err)
	}
	stored, err = os.ReadFile(tokenPath)
	if err != nil || !bytes.Equal(stored, []byte(issued.RefreshToken)) {
		t.Fatalf("rotated token: %v", err)
	}
	if err := saveIssued(issued, signer, key+".pub", "admin", key, certPath, ""); err == nil {
		t.Fatal("untrusted CA accepted")
	}
	stored, _ = os.ReadFile(tokenPath)
	if !bytes.Equal(stored, []byte(issued.RefreshToken)) {
		t.Fatal("token changed after rejected certificate")
	}
}
