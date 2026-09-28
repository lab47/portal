package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestCertCommands(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	operator := filepath.Join(dir, "operator")
	certPath := filepath.Join(dir, "operator-cert.pub")
	for _, path := range []string{ca, operator} {
		if err := run([]string{"cert", "keygen", "--out", path}); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("private key mode: %v, %v", info, err)
		}
		if err := run([]string{"cert", "keygen", "--out", path}); !os.IsExist(err) {
			t.Fatalf("existing key was overwritten: %v", err)
		}
	}
	args := []string{"cert", "sign", "--ca-key", ca, "--pub", operator + ".pub", "--principal", "admin", "--id", "operator", "--out", certPath, "--valid-for", "30m"}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	if err := run(args); !os.IsExist(err) {
		t.Fatalf("existing certificate was overwritten: %v", err)
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	cert, ok := pub.(*ssh.Certificate)
	if err != nil || !ok || cert.KeyId != "operator" || cert.CertType != ssh.UserCert || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "admin" || time.Until(time.Unix(int64(cert.ValidBefore), 0)) < 29*time.Minute {
		t.Fatalf("issued certificate: %v, %v", cert, err)
	}
	if err := run([]string{"cert", "inspect", "--cert", certPath, "--ca", ca + ".pub", "--principal", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"cert", "inspect", "--cert", certPath, "--ca", ca + ".pub", "--principal", "other"}); err == nil || !strings.Contains(err.Error(), "principal") {
		t.Fatalf("wrong principal accepted: %v", err)
	}
	if err := run([]string{"cert", "inspect", "--cert", certPath, "--ca", operator + ".pub", "--principal", "admin"}); err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("wrong CA accepted: %v", err)
	}
	invalid := append(append([]string{}, args[:len(args)-1]...), "0s")
	invalid[11] = filepath.Join(dir, "invalid-cert.pub") // output path
	if err := run(invalid); err == nil || !strings.Contains(err.Error(), "positive") {
		t.Fatalf("zero lifetime accepted: %v", err)
	}
}
