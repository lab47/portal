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

const challengeDomain = "adminhelper-command-v1\x00"

func commandProof(nonce []byte, argv []string) []byte {
	encoded, _ := json.Marshal(argv)
	proof := append([]byte(challengeDomain), nonce...)
	return append(proof, encoded...)
}

func verifyCommand(ca ssh.PublicKey, principal string, nonce []byte, req commandRequest) error {
	key, err := ssh.ParsePublicKey(req.Certificate)
	if err != nil {
		return err
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok || len(req.Argv) == 0 {
		return errors.New("user certificate and command required")
	}
	if err := VerifyUserCertificate(ca, principal, cert); err != nil {
		return err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(req.Signature, &sig); err != nil {
		return err
	}
	if err := cert.Key.Verify(commandProof(nonce, req.Argv), &sig); err != nil {
		return fmt.Errorf("invalid command signature: %w", err)
	}
	return nil
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

func signCommand(signer ssh.Signer, cert *ssh.Certificate, nonce []byte, argv []string) (commandRequest, error) {
	sig, err := signer.Sign(rand.Reader, commandProof(nonce, argv))
	if err != nil {
		return commandRequest{}, err
	}
	return commandRequest{Certificate: cert.Marshal(), Signature: ssh.Marshal(sig), Argv: argv}, nil
}
