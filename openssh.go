package portal

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func (a peerAuthenticator) forSSHAccount(account, current *user.User) (peerAuthenticator, policy, error) {
	if account.Uid != current.Uid && (runtime.GOOS == "windows" || current.Uid != "0") {
		return peerAuthenticator{}, nil, errors.New("server cannot access another account")
	}
	path := ""
	if account.Uid == current.Uid {
		path = a.keyFile
	}
	return openSSHAccountAuthentication(path, account)
}

func openSSHAuthentication(path string) (peerAuthenticator, policy, error) {
	account, err := user.Current()
	if err != nil {
		return peerAuthenticator{}, nil, err
	}
	return openSSHAccountAuthentication(path, account)
}

func openSSHAccountAuthentication(path string, account *user.User) (peerAuthenticator, policy, error) {
	if path == "" {
		// Use the target account's home, not inherited HOME/SUDO_USER.
		path = filepath.Join(account.HomeDir, ".ssh", "authorized_keys")
	}
	f, err := os.Open(path)
	if err != nil {
		return peerAuthenticator{}, nil, fmt.Errorf("OpenSSH authorized_keys: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return peerAuthenticator{}, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return peerAuthenticator{}, nil, errors.New("authorized_keys must be a regular file of at most 1 MiB")
	}
	if err := checkSSHTrustFile(info, account.Uid); err != nil {
		return peerAuthenticator{}, nil, fmt.Errorf("unsafe authorized_keys file: %w", err)
	}
	// Like OpenSSH StrictModes, never trust a file another account can change.
	for _, name := range []string{filepath.Dir(path), filepath.Dir(filepath.Dir(path))} {
		stat, err := os.Stat(name)
		if err != nil {
			return peerAuthenticator{}, nil, err
		}
		if err := checkSSHTrustFile(stat, account.Uid); err != nil {
			return peerAuthenticator{}, nil, fmt.Errorf("unsafe authorized_keys path %s: %w", name, err)
		}
	}
	keys := make(map[string]ssh.PublicKey)
	p := make(policy)
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return peerAuthenticator{}, nil, err
	}
	if len(data) > 1024*1024 {
		return peerAuthenticator{}, nil, errors.New("authorized_keys exceeds 1 MiB")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(text))
		if err != nil || len(strings.TrimSpace(string(rest))) != 0 {
			return peerAuthenticator{}, nil, fmt.Errorf("invalid authorized_keys entry on line %d", line)
		}
		// Portal cannot enforce SSH options such as command=, from= or
		// restrict, and cert-authority is not a login key. Skip, never loosen.
		if _, cert := key.(*ssh.Certificate); cert || len(options) != 0 {
			continue
		}
		identity := ssh.FingerprintSHA256(key)
		keys[identity] = key
		p[identity] = map[string]bool{account.Uid: true}
	}
	if err := scanner.Err(); err != nil {
		return peerAuthenticator{}, nil, err
	}
	if len(keys) == 0 {
		return peerAuthenticator{}, nil, errors.New("authorized_keys contains no unrestricted plain SSH keys")
	}
	return peerAuthenticator{keys: keys}, p, nil
}

func openSSHSigner(ctx context.Context, path string) (ssh.Signer, func(), error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil, err
		}
		for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			candidate := filepath.Join(home, ".ssh", name)
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, nil, err
			}
		}
	}
	var wanted ssh.PublicKey
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err == nil {
			return signer, func() {}, nil
		}
		var encrypted *ssh.PassphraseMissingError
		if !errors.As(err, &encrypted) {
			return nil, nil, fmt.Errorf("OpenSSH key %s: %w", path, err)
		}
		wanted = encrypted.PublicKey
		if wanted == nil {
			pub, err := os.ReadFile(path + ".pub")
			if err != nil {
				return nil, nil, fmt.Errorf("encrypted key needs its .pub file and ssh-add: %w", err)
			}
			wanted, _, _, _, err = ssh.ParseAuthorizedKey(pub)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, nil, errors.New("SSH authentication needs ~/.ssh/id_ed25519, id_ecdsa or id_rsa, --key, or SSH_AUTH_SOCK; load encrypted keys with ssh-add")
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, nil, fmt.Errorf("OpenSSH agent: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	closeAgent := func() { stop(); conn.Close() }
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	signers, err := agent.NewClient(conn).Signers()
	conn.SetDeadline(time.Time{})
	if err == nil {
		for _, signer := range signers {
			key := signer.PublicKey()
			if _, cert := key.(*ssh.Certificate); cert {
				continue
			}
			if wanted == nil || ssh.FingerprintSHA256(wanted) == ssh.FingerprintSHA256(key) {
				return signer, closeAgent, nil
			}
		}
	}
	closeAgent()
	if err != nil {
		return nil, nil, fmt.Errorf("OpenSSH agent: %w", err)
	}
	return nil, nil, errors.New("OpenSSH agent has no matching plain key; run ssh-add or choose --key")
}
