package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	adminhelper "github.com/miren/portal"
	"golang.org/x/crypto/ssh"
	"miren.dev/mflags"
)

func registerCertCommands(dispatcher *mflags.Dispatcher) {
	keyFlags := mflags.NewFlagSet("cert keygen")
	keyOut := keyFlags.String("out", 0, "", "private key path (public key is written to <out>.pub)")
	dispatcher.Dispatch("cert keygen", mflags.NewCommand(keyFlags, func(_ *mflags.FlagSet, _ []string) error {
		if *keyOut == "" {
			return errors.New("-out is required")
		}
		if err := generateKey(*keyOut); err != nil {
			return err
		}
		fmt.Printf("Created %s and %s.pub\n", *keyOut, *keyOut)
		return nil
	}, mflags.WithUsage("Generate an Ed25519 CA or user key pair")))

	signFlags := mflags.NewFlagSet("cert sign")
	caKey := signFlags.String("ca-key", 0, "", "CA private key path")
	userKey := signFlags.String("pub", 0, "", "user public key path")
	principal := signFlags.String("principal", 0, "", "authorized server principal")
	id := signFlags.String("id", 0, "", "certificate identity for audit")
	out := signFlags.String("out", 0, "", "user certificate output path")
	validFor := signFlags.Duration("valid-for", 0, time.Hour, "certificate lifetime")
	dispatcher.Dispatch("cert sign", mflags.NewCommand(signFlags, func(_ *mflags.FlagSet, _ []string) error {
		if *caKey == "" || *userKey == "" || *principal == "" || *id == "" || *out == "" {
			return errors.New("-ca-key, -pub, -principal, -id and -out are required")
		}
		if err := issueCertificate(*caKey, *userKey, *principal, *id, *out, *validFor); err != nil {
			return err
		}
		fmt.Printf("Created %s\n", *out)
		return nil
	}, mflags.WithUsage("Sign an SSH user certificate with a CA key")))

	inspectFlags := mflags.NewFlagSet("cert inspect")
	certFile := inspectFlags.String("cert", 0, "", "user certificate path")
	caFile := inspectFlags.String("ca", 0, "", "trusted CA public key path")
	inspectPrincipal := inspectFlags.String("principal", 0, "", "required server principal")
	dispatcher.Dispatch("cert inspect", mflags.NewCommand(inspectFlags, func(_ *mflags.FlagSet, _ []string) error {
		if *certFile == "" || *caFile == "" || *inspectPrincipal == "" {
			return errors.New("-cert, -ca and -principal are required")
		}
		cert, err := inspectCertificate(*certFile, *caFile, *inspectPrincipal)
		if err != nil {
			return err
		}
		fmt.Printf("ID: %s\nSerial: %d\nPrincipal: %s\nValid: %s to %s\nCA: %s\n",
			cert.KeyId, cert.Serial, *inspectPrincipal,
			time.Unix(int64(cert.ValidAfter), 0).UTC().Format(time.RFC3339),
			time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339),
			ssh.FingerprintSHA256(cert.SignatureKey))
		return nil
	}, mflags.WithUsage("Inspect and verify an SSH user certificate")))
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err = f.Close(); err != nil {
		os.Remove(path)
	}
	return err
}

func generateKey(path string) error {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	if err := writeNewFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		return err
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err == nil {
		err = writeNewFile(path+".pub", ssh.MarshalAuthorizedKey(sshPublic), 0644)
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

func issueCertificate(caPath, pubPath, principal, id, out string, validFor time.Duration) error {
	if validFor <= 0 {
		return errors.New("-valid-for must be positive")
	}
	caData, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	ca, err := ssh.ParsePrivateKey(caData)
	if err != nil {
		return err
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
	if err != nil {
		return err
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return errors.New("-pub must be a plain public key")
	}
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return err
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key: key, Serial: binary.BigEndian.Uint64(serial[:]), CertType: ssh.UserCert,
		KeyId: id, ValidPrincipals: []string{principal},
		ValidAfter: uint64(now.Add(-time.Minute).Unix()), ValidBefore: uint64(now.Add(validFor).Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return err
	}
	return writeNewFile(out, ssh.MarshalAuthorizedKey(cert), 0644)
}

func inspectCertificate(certPath, caPath, principal string) (*ssh.Certificate, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not an SSH certificate")
	}
	caData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	ca, _, _, _, err := ssh.ParseAuthorizedKey(caData)
	if err != nil {
		return nil, err
	}
	if err := adminhelper.VerifyUserCertificate(ca, principal, cert); err != nil {
		return nil, err
	}
	return cert, nil
}
