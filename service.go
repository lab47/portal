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
	"os/exec"
	"time"

	"github.com/lab47/portal/query"
	"github.com/tmc/go-iroh/iroh"
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

func serve(ctx context.Context, ep *iroh.Endpoint, auth peerAuthenticator, policy policy, networkDebug ...bool) error {
	return serveWithSource(ctx, ep, auth, policy, query.CollectEvents, networkDebug...)
}

func serveWithSource(ctx context.Context, ep *iroh.Endpoint, auth peerAuthenticator, policy policy, source eventSource, networkDebug ...bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	store := newMonitorStore(ctx, source)
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
			connectionCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			stop := context.AfterFunc(conn.Context(), cancel)
			defer stop()
			if len(networkDebug) != 0 && networkDebug[0] {
				defer watchConnectionPaths(connectionCtx, conn)()
			}
			for {
				stream, err := conn.AcceptStream(connectionCtx)
				if err != nil {
					return
				}
				go handleStream(connectionCtx, stream, auth, policy, source, store)
			}
		}()
	}
}

func handleStream(ctx context.Context, stream *iroh.Stream, auth peerAuthenticator, policy policy, source eventSource, store *monitorStore) {
	var opener [1]byte
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(stream, opener[:]); err != nil {
		stream.Close()
		return
	}
	switch opener[0] {
	case 1:
		handleCommand(ctx, stream, auth, policy)
	case 2:
		handleMonitor(ctx, stream, auth, policy, source)
	case 3:
		handleRegisteredMonitor(ctx, stream, auth, policy, store)
	default:
		stream.Close()
	}
}

func handleCommand(ctx context.Context, stream *iroh.Stream, auth peerAuthenticator, policy policy) {
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(65 * time.Second))
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
	if len(req.Argv) == 0 {
		writeResponse(stream, Result{Error: "command required"})
		return
	}
	cert, policy, err := auth.verifyForAccount(req.Certificate, req.Signature, commandProof(nonce, req.User, req.Argv), req.User, policy)
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
	// A pooled connection outlives requests. Cancel only this command when
	// its client closes the request stream, not commands on sibling streams.
	go func() {
		io.Copy(io.Discard, stream)
		cancel()
	}()
	defer stream.CancelRead(0)
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

func runRemote(ctx context.Context, ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert ssh.PublicKey, user string, argv []string, existing ...*iroh.Conn) (Result, error) {
	conn, release, err := remoteConnection(ctx, ep, reg, existing)
	if err != nil {
		return Result{}, err
	}
	defer release()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return Result{}, err
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
	defer stop()
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
