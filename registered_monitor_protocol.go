package portal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/crypto/ssh"
)

type monitorAction struct {
	Action         string          `json:"action"` // create, read, delete
	ID             string          `json:"id,omitempty"`
	After          uint64          `json:"after,omitempty"`
	AfterTimestamp string          `json:"after_timestamp,omitempty"`
	Request        *MonitorRequest `json:"request,omitempty"`
	TTL            time.Duration   `json:"ttl,omitempty"` // idle lifetime in nanoseconds; zero selects default
}

type registeredMonitorRequest struct {
	Certificate []byte `json:"certificate"`
	Signature   []byte `json:"signature"`
	monitorAction
}

type registeredMonitorFrame struct {
	ID     string         `json:"id,omitempty"`
	Record *MonitorRecord `json:"record,omitempty"`
	Error  string         `json:"error,omitempty"`
	Oldest uint64         `json:"oldest,omitempty"`
}

func authorizeMonitorSource(p policy, cert *ssh.Certificate, source string) error {
	if source == "capabilities" {
		// Any mapped identity may discover requirements, including when it
		// cannot query the server's own account. Never expose policy contents.
		if len(p[cert.KeyId]) == 0 {
			return errors.New("not authorized")
		}
		return nil
	}
	privileged := source == "packets" || source == "disk" || source == "containers" || source == "cgroups" || source == "tracepoint"
	if privileged && os.Geteuid() != 0 {
		return fmt.Errorf("%s monitoring requires a root server", source)
	}
	account := ""
	if privileged {
		account = "root"
	}
	if _, err := p.authorize(cert.KeyId, account); err != nil {
		return errors.New("not authorized")
	}
	return nil
}

func monitorOwner(cert *ssh.Certificate) string {
	digest := sha256.Sum256(cert.Key.Marshal())
	return fmt.Sprintf("%x", digest)
}

func handleRegisteredMonitor(ctx context.Context, stream *iroh.Stream, ca ssh.PublicKey, principal string, policy policy, store *monitorStore) {
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(15 * time.Second))
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	if err := json.NewEncoder(stream).Encode(nonce); err != nil {
		return
	}
	var req registeredMonitorRequest
	if err := json.NewDecoder(io.LimitReader(stream, 64*1024)).Decode(&req); err != nil {
		return
	}
	cert, err := verifyRegisteredMonitor(ca, principal, nonce, req)
	if err != nil {
		writeRegisteredFrame(stream, registeredMonitorFrame{Error: "authentication failed"})
		return
	}
	owner := monitorOwner(cert)
	switch req.Action {
	case "create":
		if req.ID != "" || req.After != 0 || req.AfterTimestamp != "" || req.Request == nil {
			writeRegisteredFrame(stream, registeredMonitorFrame{Error: "invalid create request"})
			return
		}
		if err := authorizeMonitorSource(policy, cert, req.Request.Source); err != nil {
			writeRegisteredFrame(stream, registeredMonitorFrame{Error: err.Error()})
			return
		}
		id, err := store.create(owner, *req.Request, req.TTL)
		if err != nil {
			writeRegisteredFrame(stream, registeredMonitorFrame{Error: err.Error()})
			return
		}
		writeRegisteredFrame(stream, registeredMonitorFrame{ID: id})
	case "read", "delete":
		if len(req.ID) != 32 || req.Request != nil || req.TTL != 0 || (req.Action == "delete" && (req.After != 0 || req.AfterTimestamp != "")) || (req.After != 0 && req.AfterTimestamp != "") {
			writeRegisteredFrame(stream, registeredMonitorFrame{Error: "invalid monitor request"})
			return
		}
		if req.AfterTimestamp != "" {
			if err := validateTAI64N(req.AfterTimestamp); err != nil {
				writeRegisteredFrame(stream, registeredMonitorFrame{Error: err.Error()})
				return
			}
		}
		m, err := store.get(req.ID, owner)
		if err == nil {
			err = authorizeMonitorSource(policy, cert, m.request.Source)
		}
		if err != nil {
			writeRegisteredFrame(stream, registeredMonitorFrame{Error: err.Error()})
			return
		}
		if req.Action == "delete" {
			if err := store.delete(req.ID, owner); err != nil {
				writeRegisteredFrame(stream, registeredMonitorFrame{Error: err.Error()})
				return
			}
			writeRegisteredFrame(stream, registeredMonitorFrame{ID: req.ID})
			return
		}
		stream.SetDeadline(time.Time{})
		readCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(readCtx, func() { stream.Close() })
		defer stop()
		readDone := make(chan struct{})
		go func() {
			io.Copy(io.Discard, stream)
			cancel()
			close(readDone)
		}()
		encoder := json.NewEncoder(stream)
		err = store.read(readCtx, req.ID, owner, req.After, req.AfterTimestamp, func(record MonitorRecord) error {
			return encoder.Encode(registeredMonitorFrame{Record: &record})
		})
		if err != nil && readCtx.Err() == nil {
			frame := registeredMonitorFrame{Error: err.Error()}
			var gap *MonitorHistoryLostError
			if errors.As(err, &gap) {
				frame.Oldest = gap.OldestSequence
			}
			if encoder.Encode(frame) == nil && stream.CloseWrite() == nil {
				stream.SetReadDeadline(time.Now().Add(5 * time.Second))
				<-readDone
			}
		}
	default:
		writeRegisteredFrame(stream, registeredMonitorFrame{Error: "unsupported monitor action"})
	}
}

func writeRegisteredFrame(stream *iroh.Stream, frame registeredMonitorFrame) {
	if json.NewEncoder(stream).Encode(frame) == nil && stream.CloseWrite() == nil {
		io.Copy(io.Discard, stream)
	}
}

// CreateMonitor starts a server-owned event source that continues after this
// call returns. Registrations survive client disconnects, not server restarts.
// An optional positive TTL overrides DefaultMonitorTTL; zero uses the default.
// Active reads keep the monitor alive; the TTL restarts after the last read ends.
func (c Client) CreateMonitor(ctx context.Context, request MonitorRequest, ttl ...time.Duration) (string, error) {
	lifetime, err := monitorTTL(ttl)
	if err != nil {
		return "", err
	}
	if err := request.validate(); err != nil {
		return "", err
	}
	if request.Mode != "" {
		return "", errors.New("registered monitors require event mode")
	}
	return withClient(c, ctx, func(ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert *ssh.Certificate) (string, error) {
		return registeredMonitorRemote(ctx, ep, reg, signer, cert, monitorAction{Action: "create", Request: &request, TTL: lifetime}, nil)
	})
}

// ReadMonitor replays records after the cursor, then follows new records until
// canceled. after=0 reads from the start; keep the last processed sequence for
// a subsequent call. A stale cursor returns an explicit history-loss error.
func (c Client) ReadMonitor(ctx context.Context, id string, after uint64, onRecord func(MonitorRecord) error) error {
	if len(id) != 32 || onRecord == nil {
		return errors.New("monitor ID and record callback required")
	}
	_, err := withClient(c, ctx, func(ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert *ssh.Certificate) (string, error) {
		return registeredMonitorRemote(ctx, ep, reg, signer, cert, monitorAction{Action: "read", ID: id, After: after}, onRecord)
	})
	return err
}

// ReadMonitorSince resumes with the first retained event strictly newer than
// timestamp, then follows new events. Unlike sequence cursors, old timestamps
// clamp to the oldest retained event rather than returning a history-loss error.
func (c Client) ReadMonitorSince(ctx context.Context, id, timestamp string, onRecord func(MonitorRecord) error) error {
	if len(id) != 32 || onRecord == nil {
		return errors.New("monitor ID and record callback required")
	}
	if err := validateTAI64N(timestamp); err != nil {
		return err
	}
	_, err := withClient(c, ctx, func(ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert *ssh.Certificate) (string, error) {
		return registeredMonitorRemote(ctx, ep, reg, signer, cert, monitorAction{Action: "read", ID: id, AfterTimestamp: timestamp}, onRecord)
	})
	return err
}

// DeleteMonitor stops the source and removes its buffered history.
func (c Client) DeleteMonitor(ctx context.Context, id string) error {
	if len(id) != 32 {
		return errors.New("monitor ID required")
	}
	_, err := withClient(c, ctx, func(ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert *ssh.Certificate) (string, error) {
		return registeredMonitorRemote(ctx, ep, reg, signer, cert, monitorAction{Action: "delete", ID: id}, nil)
	})
	return err
}

func registeredMonitorRemote(ctx context.Context, ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert *ssh.Certificate, action monitorAction, onRecord func(MonitorRecord) error) (string, error) {
	id, err := key.ParseEndpointID(reg.EndpointID)
	if err != nil {
		return "", err
	}
	relayURL, err := netaddr.ParseRelayURL(reg.RelayURL)
	if err != nil || relayURL.URL().Host == "" {
		return "", errors.New("invalid relay URL in inventory")
	}
	conn, err := ep.Connect(ctx, netaddr.NewEndpointAddr(id).WithRelayURL(relayURL), alpn)
	if err != nil {
		return "", err
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return "", err
	}
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	defer stop()
	stream.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := stream.Write([]byte{3}); err != nil {
		return "", err
	}
	var nonce []byte
	if err := json.NewDecoder(stream).Decode(&nonce); err != nil {
		return "", err
	}
	if len(nonce) != 32 {
		return "", errors.New("invalid server challenge")
	}
	req, err := signRegisteredMonitor(signer, cert, nonce, action)
	if err != nil {
		return "", err
	}
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		return "", err
	}
	stream.SetDeadline(time.Time{})
	decoder := json.NewDecoder(stream)
	for {
		var frame registeredMonitorFrame
		if err := decoder.Decode(&frame); err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", err
		}
		if frame.Error != "" {
			if frame.Oldest != 0 {
				return "", &MonitorHistoryLostError{OldestSequence: frame.Oldest}
			}
			return "", errors.New(frame.Error)
		}
		if action.Action != "read" {
			if len(frame.ID) != 32 || frame.Record != nil || (action.Action == "delete" && frame.ID != action.ID) {
				return "", errors.New("invalid monitor response")
			}
			stream.CloseWrite()
			return frame.ID, nil
		}
		if frame.Record == nil || frame.ID != "" || frame.Record.Sequence == 0 || (action.AfterTimestamp == "" && frame.Record.Sequence != action.After+1) {
			return "", errors.New("invalid monitor record")
		}
		if action.AfterTimestamp != "" && frame.Record.Event.TAI64N <= action.AfterTimestamp {
			return "", errors.New("invalid monitor timestamp resume")
		}
		if err := onRecord(*frame.Record); err != nil {
			return "", err
		}
		action.After = frame.Record.Sequence
		action.AfterTimestamp = ""
	}
}
