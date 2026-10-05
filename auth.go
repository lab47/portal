package portal

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"time"

	"golang.org/x/crypto/ssh"
)

const challengeDomain = "adminhelper-command-v2\x00"
const monitorDomain = "adminhelper-monitor-v2\x00"
const registeredMonitorDomain = "adminhelper-registered-monitor-v1\x00"

func commandProof(nonce []byte, user string, argv []string) []byte {
	encoded, _ := json.Marshal(struct {
		User string   `json:"user"`
		Argv []string `json:"argv"`
	}{user, argv})
	proof := append([]byte(challengeDomain), nonce...)
	return append(proof, encoded...)
}

func verifyCommand(ca ssh.PublicKey, principal string, nonce []byte, req commandRequest) (*authenticatedPeer, error) {
	if len(req.Argv) == 0 {
		return nil, errors.New("command required")
	}
	return (peerAuthenticator{ca: ca, principal: principal}).verify(req.Certificate, req.Signature, commandProof(nonce, req.User, req.Argv))
}

// VerifyUserCertificate checks a user certificate against the trusted CA and principal.
func VerifyUserCertificate(ca ssh.PublicKey, principal string, cert *ssh.Certificate) error {
	return verifyUserCertificateAt(ca, principal, cert, time.Now())
}

func verifyUserCertificateAt(ca ssh.PublicKey, principal string, cert *ssh.Certificate, at time.Time) error {
	if cert == nil || cert.CertType != ssh.UserCert || len(cert.ValidPrincipals) == 0 || principal == "" {
		return errors.New("user certificate and principal required")
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), ca.Marshal()) {
		return errors.New("untrusted certificate authority")
	}
	if err := (&ssh.CertChecker{Clock: func() time.Time { return at }}).CheckCert(principal, cert); err != nil {
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

func signCommand(signer ssh.Signer, cert ssh.PublicKey, nonce []byte, user string, argv []string) (commandRequest, error) {
	sig, err := signer.Sign(rand.Reader, commandProof(nonce, user, argv))
	if err != nil {
		return commandRequest{}, err
	}
	return commandRequest{Certificate: cert.Marshal(), Signature: ssh.Marshal(sig), User: user, Argv: argv}, nil
}

func monitorProof(nonce []byte, request MonitorRequest) []byte {
	encoded, _ := json.Marshal(request)
	proof := append([]byte(monitorDomain), nonce...)
	return append(proof, encoded...)
}

func signMonitor(signer ssh.Signer, cert ssh.PublicKey, nonce []byte, request MonitorRequest) (monitorRequest, error) {
	sig, err := signer.Sign(rand.Reader, monitorProof(nonce, request))
	if err != nil {
		return monitorRequest{}, err
	}
	return monitorRequest{Certificate: cert.Marshal(), Signature: ssh.Marshal(sig), MonitorRequest: request}, nil
}

func verifyMonitor(ca ssh.PublicKey, principal string, nonce []byte, req monitorRequest) (*authenticatedPeer, error) {
	return (peerAuthenticator{ca: ca, principal: principal}).verify(req.Certificate, req.Signature, monitorProof(nonce, req.MonitorRequest))
}

func registeredMonitorProof(nonce []byte, action monitorAction) []byte {
	encoded, _ := json.Marshal(action)
	proof := append([]byte(registeredMonitorDomain), nonce...)
	return append(proof, encoded...)
}

func signRegisteredMonitor(signer ssh.Signer, cert ssh.PublicKey, nonce []byte, action monitorAction) (registeredMonitorRequest, error) {
	sig, err := signer.Sign(rand.Reader, registeredMonitorProof(nonce, action))
	if err != nil {
		return registeredMonitorRequest{}, err
	}
	return registeredMonitorRequest{Certificate: cert.Marshal(), Signature: ssh.Marshal(sig), monitorAction: action}, nil
}

func verifyRegisteredMonitor(ca ssh.PublicKey, principal string, nonce []byte, req registeredMonitorRequest) (*authenticatedPeer, error) {
	return (peerAuthenticator{ca: ca, principal: principal}).verify(req.Certificate, req.Signature, registeredMonitorProof(nonce, req.monitorAction))
}

// An authenticated peer is not necessarily a certificate. Key is always the
// proof-signing key; identity is a CA key ID or an authorized-key fingerprint.
type authenticatedPeer struct {
	Key   ssh.PublicKey
	KeyId string
}

type peerAuthenticator struct {
	ca           ssh.PublicKey
	principal    string
	keys         map[string]ssh.PublicKey
	openSSH      bool
	keyFile      string // Optional override for the server account only.
	queryKeyFile string // Additional plain keys for queries/monitors, never commands.
}

func (a peerAuthenticator) verifyQuery(credential, signature, proof []byte, p policy) (*authenticatedPeer, policy, error) {
	peer, allowed, err := a.verifyForAccount(credential, signature, proof, "", p)
	if err == nil || !a.openSSH || a.queryKeyFile == "" {
		return peer, allowed, err
	}
	queryAuth, allowed, err := openSSHAuthentication(a.queryKeyFile)
	if err != nil {
		return nil, nil, err
	}
	peer, err = queryAuth.verify(credential, signature, proof)
	return peer, allowed, err
}

func (a peerAuthenticator) verifyForAccount(credential, signature, proof []byte, name string, p policy) (*authenticatedPeer, policy, error) {
	if a.openSSH {
		current, err := user.Current()
		if err != nil {
			return nil, nil, err
		}
		account := current
		if name != "" {
			account, err = user.Lookup(name)
			if err != nil {
				return nil, nil, err
			}
		}
		a, p, err = a.forSSHAccount(account, current)
		if err != nil {
			return nil, nil, err
		}
	}
	peer, err := a.verify(credential, signature, proof)
	return peer, p, err
}

func (a peerAuthenticator) verify(credential, signature, proof []byte) (*authenticatedPeer, error) {
	key, err := ssh.ParsePublicKey(credential)
	if err != nil {
		return nil, err
	}
	peer := &authenticatedPeer{Key: key, KeyId: ssh.FingerprintSHA256(key)}
	if cert, ok := key.(*ssh.Certificate); ok {
		if a.ca == nil {
			return nil, errors.New("certificate authentication is not enabled")
		}
		if err := VerifyUserCertificate(a.ca, a.principal, cert); err != nil {
			return nil, err
		}
		peer.Key, peer.KeyId = cert.Key, cert.KeyId
	} else {
		trusted, ok := a.keys[peer.KeyId]
		if a.ca != nil || !ok || !bytes.Equal(trusted.Marshal(), key.Marshal()) {
			return nil, errors.New("SSH key is not authorized")
		}
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(signature, &sig); err != nil {
		return nil, err
	}
	if err := peer.Key.Verify(proof, &sig); err != nil {
		return nil, err
	}
	return peer, nil
}
