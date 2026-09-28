package portal

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/crypto/ssh"
)

const alpn = "adminhelper/2"

type commandRequest struct {
	Certificate []byte   `json:"certificate"`
	Signature   []byte   `json:"signature"`
	User        string   `json:"user,omitempty"`
	Argv        []string `json:"argv"`
}

// Result is the remote command's combined output and exit status.
type Result struct {
	Output   string `json:"output"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

func register(ctx context.Context, url, token string, reg registration) error {
	data, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/servers", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("registration failed: %s", res.Status)
	}
	return nil
}

func serve(ctx context.Context, ep *iroh.Endpoint, ca ssh.PublicKey, principal string, policy policy) error {
	for {
		conn, err := ep.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer conn.CloseWithError(0, "")
			stream, err := conn.AcceptStream(ctx)
			if err == nil {
				handleCommand(ctx, stream, ca, principal, policy)
			} else {
				log.Printf("accept stream: %v", err)
			}
		}()
	}
}

func handleCommand(ctx context.Context, stream *iroh.Stream, ca ssh.PublicKey, principal string, policy policy) {
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(65 * time.Second))
	var opener [1]byte
	if _, err := io.ReadFull(stream, opener[:]); err != nil || opener[0] != 1 {
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	if err := json.NewEncoder(stream).Encode(nonce); err != nil {
		return
	}
	var req commandRequest
	if err := json.NewDecoder(io.LimitReader(stream, 64*1024)).Decode(&req); err != nil {
		log.Printf("read command: %v", err)
		return
	}
	cert, err := verifyCommand(ca, principal, nonce, req)
	if err != nil {
		log.Printf("rejected command: %v", err)
		writeResponse(stream, Result{Error: "authentication failed"})
		return
	}
	account, err := policy.authorize(cert.KeyId, req.User)
	if err != nil {
		log.Printf("rejected command from %q: %v", cert.KeyId, err)
		writeResponse(stream, Result{Error: err.Error()})
		return
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, req.Argv[0], req.Argv[1:]...)
	if req.User != "" {
		if err := setCommandUser(cmd, account); err != nil {
			writeResponse(stream, Result{Error: err.Error()})
			return
		}
	}
	var output bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &output, remaining: 1 << 20}
	cmd.Stderr = cmd.Stdout
	err = cmd.Run()
	response := Result{Output: output.String()}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			response.ExitCode = exit.ExitCode()
		} else {
			response.Error = err.Error()
		}
	}
	writeResponse(stream, response)
}

func setCommandUser(cmd *exec.Cmd, account *user.User) error {
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return err
	}
	if uid != uint64(os.Geteuid()) || gid != uint64(os.Getegid()) {
		if os.Geteuid() != 0 {
			return errors.New("switching users requires the server to run as root")
		}
		groups, err := account.GroupIds()
		if err != nil {
			return err
		}
		credential := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
		for _, group := range groups {
			id, err := strconv.ParseUint(group, 10, 32)
			if err != nil {
				return err
			}
			credential.Groups = append(credential.Groups, uint32(id))
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
	}
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + account.HomeDir, "USER=" + account.Username, "LOGNAME=" + account.Username}
	return nil
}

func writeResponse(stream *iroh.Stream, response Result) {
	if json.NewEncoder(stream).Encode(response) != nil || stream.CloseWrite() != nil {
		return
	}
	// Wait for the client to finish reading before closing its QUIC connection.
	io.Copy(io.Discard, stream)
}

type limitedWriter struct {
	w         io.Writer
	remaining int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		p = p[:w.remaining]
	}
	n, err := w.w.Write(p)
	w.remaining -= n
	if w.remaining == 0 && err == nil {
		return n, errors.New("command output limit exceeded")
	}
	return n, err
}

func lookup(ctx context.Context, url, name string) (registration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/servers/"+name, nil)
	if err != nil {
		return registration{}, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return registration{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return registration{}, fmt.Errorf("lookup failed: %s", res.Status)
	}
	var reg registration
	err = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&reg)
	return reg, err
}

func runRemote(ctx context.Context, ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert *ssh.Certificate, user string, argv []string) (Result, error) {
	id, err := key.ParseEndpointID(reg.EndpointID)
	if err != nil {
		return Result{}, err
	}
	relayURL, err := netaddr.ParseRelayURL(reg.RelayURL)
	if err != nil || relayURL.URL().Host == "" {
		return Result{}, errors.New("invalid relay URL in inventory")
	}
	conn, err := ep.Connect(ctx, netaddr.NewEndpointAddr(id).WithRelayURL(relayURL), alpn)
	if err != nil {
		return Result{}, err
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return Result{}, err
	}
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(70 * time.Second))
	if _, err := stream.Write([]byte{1}); err != nil {
		return Result{}, err
	}
	var nonce []byte
	if err := json.NewDecoder(stream).Decode(&nonce); err != nil {
		return Result{}, err
	}
	if len(nonce) != 32 {
		return Result{}, errors.New("invalid server challenge")
	}
	req, err := signCommand(signer, cert, nonce, user, argv)
	if err != nil {
		return Result{}, err
	}
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		return Result{}, err
	}
	var response Result
	if err := json.NewDecoder(io.LimitReader(stream, 2<<20)).Decode(&response); err != nil {
		return Result{}, err
	}
	if err := stream.CloseWrite(); err != nil {
		return Result{}, err
	}
	return response, nil
}
