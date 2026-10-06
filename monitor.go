package portal

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/lab47/portal/query"
	"github.com/tmc/go-iroh/iroh"
	"golang.org/x/crypto/ssh"
)

type monitorRequest struct {
	Certificate []byte `json:"certificate"`
	Signature   []byte `json:"signature"`
	MonitorRequest
}

type monitorFrame struct {
	Event    *Event    `json:"event,omitempty"`
	Snapshot *Snapshot `json:"snapshot,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// Monitor streams matching events until ctx is canceled. Callback errors stop
// the subscription. A remote source failure is returned as an error.
func (c Client) Monitor(ctx context.Context, request MonitorRequest, onEvent func(Event) error) error {
	if request.Mode != "" {
		return errors.New("use Client.Query for query modes")
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if onEvent == nil {
		return errors.New("event callback required")
	}
	_, err := withClient(c, ctx, func(ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert ssh.PublicKey, conn *iroh.Conn) (struct{}, error) {
		return struct{}{}, monitorRemote(ctx, ep, reg, signer, cert, request, onEvent, conn)
	})
	return err
}

// Query returns current state, or aggregates newly collected events over the
// requested aggregation window, with the server's account scope.
func (c Client) Query(ctx context.Context, request MonitorRequest) (Snapshot, error) {
	if request.Mode != "aggregate" {
		request.Mode = "snapshot"
	}
	if request.Aggregation != nil {
		request.Mode = "aggregate"
	}
	if err := request.Validate(); err != nil {
		return Snapshot{}, err
	}
	return withClient(c, ctx, func(ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert ssh.PublicKey, conn *iroh.Conn) (Snapshot, error) {
		return monitorRequestRemote(ctx, ep, reg, signer, cert, request, nil, conn)
	})
}

func monitorRemote(ctx context.Context, ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert ssh.PublicKey, request MonitorRequest, onEvent func(Event) error, existing ...*iroh.Conn) error {
	_, err := monitorRequestRemote(ctx, ep, reg, signer, cert, request, onEvent, existing...)
	return err
}

func monitorRequestRemote(ctx context.Context, ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert ssh.PublicKey, request MonitorRequest, onEvent func(Event) error, existing ...*iroh.Conn) (Snapshot, error) {
	conn, release, err := remoteConnection(ctx, ep, reg, existing)
	if err != nil {
		return Snapshot{}, err
	}
	defer release()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
	defer stop()
	stream.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := stream.Write([]byte{2}); err != nil {
		return Snapshot{}, err
	}
	var nonce []byte
	if err := json.NewDecoder(stream).Decode(&nonce); err != nil {
		return Snapshot{}, err
	}
	if len(nonce) != 32 {
		return Snapshot{}, errors.New("invalid server challenge")
	}
	req, err := signMonitor(signer, cert, nonce, request)
	if err != nil {
		return Snapshot{}, err
	}
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		return Snapshot{}, err
	}
	stream.SetDeadline(time.Time{})
	if request.Mode == "snapshot" || request.Mode == "aggregate" {
		wait := 30 * time.Second
		if request.Aggregation != nil {
			wait += request.Aggregation.Window
		}
		stream.SetReadDeadline(time.Now().Add(wait))
		var frame monitorFrame
		if err := json.NewDecoder(io.LimitReader(stream, 8<<20)).Decode(&frame); err != nil {
			return Snapshot{}, err
		}
		if frame.Error != "" {
			return Snapshot{}, errors.New(frame.Error)
		}
		if frame.Snapshot == nil || frame.Event != nil {
			return Snapshot{}, errors.New("invalid snapshot frame")
		}
		return *frame.Snapshot, nil
	}
	decoder := json.NewDecoder(stream)
	for {
		var frame monitorFrame
		if err := decoder.Decode(&frame); err != nil {
			if ctx.Err() != nil {
				return Snapshot{}, ctx.Err()
			}
			return Snapshot{}, err
		}
		if frame.Error != "" {
			return Snapshot{}, errors.New(frame.Error)
		}
		if frame.Event == nil || frame.Snapshot != nil {
			return Snapshot{}, errors.New("invalid monitor frame")
		}
		if err := onEvent(*frame.Event); err != nil {
			return Snapshot{}, err
		}
	}
}

type eventSource func(context.Context, MonitorRequest, func(Event) error) error

func handleMonitor(ctx context.Context, stream *iroh.Stream, auth peerAuthenticator, policy policy, source eventSource) {
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(15 * time.Second))
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	if err := json.NewEncoder(stream).Encode(nonce); err != nil {
		return
	}
	var req monitorRequest
	if err := json.NewDecoder(io.LimitReader(stream, 64*1024)).Decode(&req); err != nil {
		return
	}
	encoder := json.NewEncoder(stream)
	cert, policy, err := auth.verifyQuery(req.Certificate, req.Signature, monitorProof(nonce, req.MonitorRequest), policy)
	if err != nil {
		writeMonitorError(stream, "authentication failed")
		return
	}
	if err := authorizeMonitorRequest(policy, cert.KeyId, req.MonitorRequest); err != nil {
		writeMonitorError(stream, err.Error())
		return
	}
	if err := req.MonitorRequest.Validate(); err != nil {
		writeMonitorError(stream, err.Error())
		return
	}
	req.MonitorRequest, err = query.ResolveSyscallNames(req.MonitorRequest, runtime.GOARCH)
	if err != nil {
		writeMonitorError(stream, err.Error())
		return
	}
	if req.Mode == "snapshot" {
		stream.SetDeadline(time.Now().Add(30 * time.Second))
		var snapshot Snapshot
		var err error
		if req.Source == "capabilities" {
			docs := describeCapabilities(policy, cert.KeyId)
			snapshot = Snapshot{Source: "capabilities", Time: time.Now().UTC(), Capabilities: &docs}
		} else {
			snapshot, err = (query.Engine{}).Query(ctx, req.MonitorRequest)
		}
		if err != nil {
			writeMonitorError(stream, err.Error())
			return
		}
		if encoder.Encode(monitorFrame{Snapshot: &snapshot}) == nil && stream.CloseWrite() == nil {
			io.Copy(io.Discard, stream)
		}
		return
	}
	monitorCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream.SetDeadline(time.Time{})
	stop := context.AfterFunc(monitorCtx, func() { stream.Close() })
	defer stop()
	readDone := make(chan struct{})
	go func() {
		io.Copy(io.Discard, stream)
		cancel()
		close(readDone)
	}()
	if req.Mode == "aggregate" {
		result, err := (query.Engine{Events: query.EventSource(source)}).Query(monitorCtx, req.MonitorRequest)
		if monitorCtx.Err() != nil {
			return
		}
		frame := monitorFrame{Snapshot: &result}
		if err != nil {
			frame = monitorFrame{Error: err.Error()}
		}
		stream.SetDeadline(time.Now().Add(5 * time.Second))
		if encoder.Encode(frame) == nil && stream.CloseWrite() == nil {
			<-readDone
		}
		return
	}
	err = (query.Engine{Events: query.EventSource(source)}).Monitor(monitorCtx, req.MonitorRequest, func(event Event) error {
		if err := encoder.Encode(monitorFrame{Event: &event}); err != nil {
			return fmt.Errorf("send event: %w", err)
		}
		return nil
	})
	if err != nil && monitorCtx.Err() == nil {
		encoder.Encode(monitorFrame{Error: err.Error()})
		stream.CloseWrite()
		stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		<-readDone
	}
}

func writeMonitorError(stream *iroh.Stream, message string) {
	if json.NewEncoder(stream).Encode(monitorFrame{Error: message}) == nil && stream.CloseWrite() == nil {
		io.Copy(io.Discard, stream)
	}
}
