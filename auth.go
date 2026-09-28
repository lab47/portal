package adminhelper

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

const challengeDomain = "adminhelper-command-v2\x00"

func commandProof(nonce []byte, user string, argv []string) []byte {
	encoded, _ := json.Marshal(struct {
		User string   `json:"user"`
		Argv []string `json:"argv"`
	}{user, argv})
	proof := append([]byte(challengeDomain), nonce...)
	return append(proof, encoded...)
}

func verifyCommand(ca ssh.PublicKey, principal string, nonce []byte, req commandRequest) (*ssh.Certificate, error) {
	key, err := ssh.ParsePublicKey(req.Certificate)
	if err != nil {
		return nil, err
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok || len(req.Argv) == 0 {
		return nil, errors.New("user certificate and command required")
	}
	if err := VerifyUserCertificate(ca, principal, cert); err != nil {
		return nil, err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(req.Signature, &sig); err != nil {
		return nil, err
	}
	if err := cert.Key.Verify(commandProof(nonce, req.User, req.Argv), &sig); err != nil {
		return nil, fmt.Errorf("invalid command signature: %w", err)
	}
	return cert, nil
}

// VerifyUserCertificate checks a user certificate against the trusted CA and principal.
func VerifyUserCertificate(ca ssh.PublicKey, principal string, cert *ssh.Certificate) error {
	if cert == nil || cert.CertType != ssh.UserCert || len(cert.ValidPrincipals) == 0 || principal == "" {
		return errors.New("user certificate and principal required")
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), ca.Marshal()) {
		return errors.New("untrusted certificate authority")
	}
	if err := (&ssh.CertChecker{}).CheckCert(principal, cert); err != nil {
		return err
	}
	return nil
}

func loadSigner(keyPath, certPath string) (ssh.Signer, *ssh.Certificate, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, nil, err
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		return nil, nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok || !bytes.Equal(cert.Key.Marshal(), signer.PublicKey().Marshal()) {
		return nil, nil, errors.New("certificate does not match private key")
	}
	return signer, cert, nil
}

func signCommand(signer ssh.Signer, cert *ssh.Certificate, nonce []byte, user string, argv []string) (commandRequest, error) {
	sig, err := signer.Sign(rand.Reader, commandProof(nonce, user, argv))
	if err != nil {
		return commandRequest{}, err
	}
	return commandRequest{Certificate: cert.Marshal(), Signature: ssh.Marshal(sig), User: user, Argv: argv}, nil
}
