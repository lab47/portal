package portal

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/crypto/ssh"
)

// MonitorRequest selects a source and its server-side filters. Source is
// "syscalls", "packets", "process", "disk", "tracepoint", or a snapshot-only source;
// unrelated filters must be omitted.
type MonitorRequest struct {
	Source      string              `json:"source"`
	Mode        string              `json:"mode,omitempty"` // empty for events, "snapshot" or "aggregate" for queries
	Aggregation *AggregationRequest `json:"aggregation,omitempty"`
	PID         uint32              `json:"pid,omitempty"`
	Syscalls    []int               `json:"syscalls,omitempty"`
	Packet      *PacketFilter       `json:"packet,omitempty"`
	Process     *ProcessFilter      `json:"process,omitempty"`
	Disk        *DiskFilter         `json:"disk,omitempty"`
	Tracepoint  *TracepointFilter   `json:"tracepoint,omitempty"`
	Name        string              `json:"name,omitempty"` // network interface or sensor key (exact or edge glob)
}

// TracepointFilter selects scalar fields from a Linux tracepoint. Equals values
// use decimal or 0x notation; every filtered field must also be selected.
type TracepointFilter struct {
	Event  string            `json:"event"` // category:name
	Fields []string          `json:"fields"`
	Equals map[string]string `json:"equals,omitempty"`
}

// TracepointEvent contains values interpreted using the server kernel's format.
// json.Number preserves full-width signed and unsigned 64-bit values on clients.
type TracepointEvent struct {
	Event  string                 `json:"event"`
	Fields map[string]json.Number `json:"fields"`
}

var tracepointIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]*$`)

func (f TracepointFilter) validate() error {
	parts := strings.Split(f.Event, ":")
	if len(parts) != 2 || !tracepointIdentifier.MatchString(parts[0]) || !tracepointIdentifier.MatchString(parts[1]) || len(f.Event) > 128 {
		return errors.New("tracepoint event must be category:name")
	}
	if len(f.Fields) == 0 || len(f.Fields) > 16 {
		return errors.New("tracepoint requires 1 to 16 fields")
	}
	seen := make(map[string]bool, len(f.Fields))
	for _, name := range f.Fields {
		if len(name) > 64 || !tracepointIdentifier.MatchString(name) || seen[name] {
			return fmt.Errorf("invalid or duplicate tracepoint field %q", name)
		}
		seen[name] = true
	}
	for name, value := range f.Equals {
		if !seen[name] {
			return fmt.Errorf("tracepoint filter field %q must be selected", name)
		}
		if _, err := parseTracepointNumber(value); err != nil {
			return fmt.Errorf("invalid tracepoint value %q: %w", value, err)
		}
	}
	return nil
}

func parseTracepointNumber(value string) (uint64, error) {
	if strings.HasPrefix(value, "-") {
		n, err := strconv.ParseInt(value, 10, 64)
		return uint64(n), err
	}
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 0
	}
	return strconv.ParseUint(value, base, 64)
}

// DiskFilter selects block requests by kernel device ID and operation.
type DiskFilter struct {
	Device    uint32 `json:"device,omitempty"`
	Operation string `json:"operation,omitempty"` // read, write, discard, or flush
}

// DiskEvent describes a block request issued to a device. Sector units are 512 bytes.
type DiskEvent struct {
	Device    uint32 `json:"device"`
	Sector    uint64 `json:"sector"`
	Sectors   uint32 `json:"sectors"`
	Operation string `json:"operation"`
}

// ProcessFilter selects process lifecycle events. Empty fields match all.
type ProcessFilter struct {
	Name   string `json:"name,omitempty"`   // exact, prefix*, or *suffix
	Action string `json:"action,omitempty"` // start or exit
}

// ProcessEvent describes a start or exit observed by the process poller.
type ProcessEvent struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

// ProcessInfo is a process visible to the server at snapshot time.
type ProcessInfo struct {
	PID     uint32    `json:"pid"`
	Name    string    `json:"name"`
	Started time.Time `json:"started"`
}

// Snapshot is a one-shot view, not a stream of lifecycle events.
type Snapshot struct {
	Source      string             `json:"source"`
	Time        time.Time          `json:"time"`
	Processes   []ProcessInfo      `json:"processes,omitempty"`
	CPU         []CPUInfo          `json:"cpu,omitempty"`
	Memory      *MemoryInfo        `json:"memory,omitempty"`
	Network     []InterfaceInfo    `json:"network,omitempty"`
	Kernel      *KernelInfo        `json:"kernel,omitempty"`
	Sensors     []SensorInfo       `json:"sensors,omitempty"`
	Containers  []ContainerInfo    `json:"containers,omitempty"`
	GPUs        []GPUInfo          `json:"gpus,omitempty"`
	Aggregation *AggregationResult `json:"aggregation,omitempty"`
}

// MarshalJSON keeps empty collections visible for the selected source while
// excluding fields from unrelated sources.
func (s Snapshot) MarshalJSON() ([]byte, error) {
	type fields Snapshot
	encoded, err := json.Marshal(fields(s))
	if err != nil {
		return nil, err
	}
	if s.Aggregation != nil {
		return encoded, nil
	}
	var collection string
	switch s.Source {
	case "process":
		collection = "processes"
	case "cpu":
		collection = "cpu"
	case "network":
		collection = "network"
	case "sensors":
		collection = "sensors"
	case "containers":
		collection = "containers"
	case "gpu":
		collection = "gpus"
	}
	if collection == "" {
		return encoded, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		return nil, err
	}
	if _, ok := object[collection]; !ok {
		object[collection] = json.RawMessage(`[]`)
	}
	return json.Marshal(object)
}

// PacketFilter matches packet headers. Empty fields match any value. Direction
// is "incoming" or "outgoing" relative to the server's network interface.
// Protocol is "tcp" or "udp"; port filters only match those protocols.
type PacketFilter struct {
	Protocol        string `json:"protocol,omitempty"`
	Direction       string `json:"direction,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	SourcePort      uint16 `json:"source_port,omitempty"`
	DestinationPort uint16 `json:"destination_port,omitempty"`
}

// PacketEvent contains packet endpoints and up to 2048 raw link-layer bytes.
// Data is base64-encoded in JSON. No TCP stream reassembly is performed.
type PacketEvent struct {
	Protocol        string `json:"protocol"`
	Direction       string `json:"direction"`
	SourceIP        string `json:"source_ip"`
	DestinationIP   string `json:"destination_ip"`
	SourcePort      uint16 `json:"source_port,omitempty"`
	DestinationPort uint16 `json:"destination_port,omitempty"`
	Length          int    `json:"length"`
	Data            []byte `json:"data"`
}

// Event is a syscall entry, captured packet, process transition, disk request,
// or selected tracepoint record.
type Event struct {
	Time       time.Time        `json:"time"`
	TAI64N     string           `json:"tai64n"`
	PID        uint32           `json:"pid,omitempty"`
	TID        uint32           `json:"tid,omitempty"`
	Syscall    int              `json:"syscall,omitempty"`
	Packet     *PacketEvent     `json:"packet,omitempty"`
	Process    *ProcessEvent    `json:"process,omitempty"`
	Disk       *DiskEvent       `json:"disk,omitempty"`
	Tracepoint *TracepointEvent `json:"tracepoint,omitempty"`
}

// MarshalJSON keeps syscall number zero visible without putting a spurious
// syscall field on non-syscall events.
func (e Event) MarshalJSON() ([]byte, error) {
	type fields Event
	if e.Packet != nil || e.Process != nil || e.Disk != nil || e.Tracepoint != nil {
		return json.Marshal(fields(e))
	}
	return json.Marshal(struct {
		Time    time.Time `json:"time"`
		TAI64N  string    `json:"tai64n"`
		PID     uint32    `json:"pid"`
		TID     uint32    `json:"tid"`
		Syscall int       `json:"syscall"`
	}{e.Time, e.TAI64N, e.PID, e.TID, e.Syscall})
}

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

func (r MonitorRequest) validate() error {
	if r.Mode != "" && r.Mode != "snapshot" && r.Mode != "aggregate" {
		return errors.New("unsupported monitor mode")
	}
	if r.Mode == "aggregate" {
		if r.Aggregation == nil {
			return errors.New("aggregation spec required")
		}
		if err := r.Aggregation.validate(r); err != nil {
			return err
		}
	} else if r.Aggregation != nil {
		return errors.New("aggregation requires aggregate mode")
	}
	if r.Mode == "snapshot" && r.Source != "process" && r.Source != "cpu" && r.Source != "memory" && r.Source != "network" && r.Source != "kernel" && r.Source != "sensors" && r.Source != "containers" && r.Source != "gpu" {
		return errors.New("unsupported snapshot source")
	}
	if r.Name != "" && !validEdgeGlob(r.Name) {
		return errors.New("name supports only a single leading or trailing *")
	}
	switch r.Source {
	case "tracepoint":
		if r.PID != 0 || len(r.Syscalls) != 0 || r.Packet != nil || r.Process != nil || r.Disk != nil || r.Name != "" || r.Tracepoint == nil {
			return errors.New("tracepoint source requires a tracepoint spec and no unrelated filters")
		}
		return r.Tracepoint.validate()
	case "syscalls":
		if r.Packet != nil || r.Process != nil || r.Disk != nil || r.Tracepoint != nil || r.Name != "" {
			return errors.New("unrelated filter for syscalls source")
		}
	case "process":
		if len(r.Syscalls) != 0 || r.Packet != nil || r.Disk != nil || r.Tracepoint != nil || r.Name != "" {
			return errors.New("unrelated filter for process source")
		}
		if r.Process != nil && !validEdgeGlob(r.Process.Name) {
			return errors.New("process name supports only a single leading or trailing *")
		}
		if r.Process != nil && r.Process.Action != "" && r.Process.Action != "start" && r.Process.Action != "exit" {
			return errors.New("process action must be start or exit")
		}
		if r.Mode == "snapshot" && r.Process != nil && r.Process.Action != "" {
			return errors.New("process action is not a snapshot filter")
		}
	case "packets":
		if r.PID != 0 || len(r.Syscalls) != 0 || r.Process != nil || r.Disk != nil || r.Tracepoint != nil || r.Name != "" {
			return errors.New("unrelated filter for packets source")
		}
		if r.Packet != nil {
			p := r.Packet
			if p.Protocol != "" && p.Protocol != "tcp" && p.Protocol != "udp" {
				return errors.New("packet protocol must be tcp or udp")
			}
			if p.Direction != "" && p.Direction != "incoming" && p.Direction != "outgoing" {
				return errors.New("packet direction must be incoming or outgoing")
			}
			for _, ip := range []string{p.SourceIP, p.DestinationIP} {
				if ip != "" {
					if _, err := netip.ParseAddr(ip); err != nil {
						return fmt.Errorf("invalid packet IP address %q: %w", ip, err)
					}
				}
			}
			if (p.SourcePort != 0 || p.DestinationPort != 0) && p.Protocol == "" {
				return errors.New("port filters require tcp or udp protocol")
			}
		}
	case "disk":
		if r.PID != 0 || len(r.Syscalls) != 0 || r.Packet != nil || r.Process != nil || r.Tracepoint != nil || r.Name != "" {
			return errors.New("unrelated filter for disk source")
		}
		if r.Disk != nil && r.Disk.Operation != "" && r.Disk.Operation != "read" && r.Disk.Operation != "write" && r.Disk.Operation != "discard" && r.Disk.Operation != "flush" {
			return errors.New("disk operation must be read, write, discard or flush")
		}
	case "cpu", "memory", "network", "kernel", "sensors", "containers", "gpu":
		if r.Mode != "snapshot" || r.PID != 0 || len(r.Syscalls) != 0 || r.Packet != nil || r.Process != nil || r.Disk != nil || r.Tracepoint != nil ||
			(r.Name != "" && r.Source != "network" && r.Source != "sensors" && r.Source != "containers" && r.Source != "gpu") {
			return errors.New("invalid snapshot source filters")
		}
	default:
		return errors.New("unsupported monitor source")
	}
	if len(r.Syscalls) > 256 {
		return errors.New("too many syscall filters")
	}
	for _, id := range r.Syscalls {
		if id < 0 || id > 65535 {
			return errors.New("invalid syscall number")
		}
	}
	return nil
}

func (r MonitorRequest) matches(event Event) bool {
	if r.Source == "tracepoint" {
		if event.Tracepoint == nil || r.Tracepoint == nil || event.Tracepoint.Event != r.Tracepoint.Event {
			return false
		}
		for name, expected := range r.Tracepoint.Equals {
			value, ok := event.Tracepoint.Fields[name]
			if !ok {
				return false
			}
			a, errA := parseTracepointNumber(value.String())
			b, errB := parseTracepointNumber(expected)
			if errA != nil || errB != nil || a != b {
				return false
			}
		}
		return true
	}
	if r.Source == "disk" {
		if event.Disk == nil {
			return false
		}
		return r.Disk == nil || ((r.Disk.Device == 0 || r.Disk.Device == event.Disk.Device) &&
			(r.Disk.Operation == "" || r.Disk.Operation == event.Disk.Operation))
	}
	if r.Source == "process" {
		if event.Process == nil || (r.PID != 0 && r.PID != event.PID) {
			return false
		}
		return r.Process == nil ||
			(processNameMatches(r.Process.Name, event.Process.Name) &&
				(r.Process.Action == "" || r.Process.Action == event.Process.Action))
	}
	if r.Source == "packets" {
		if event.Packet == nil {
			return false
		}
		if r.Packet == nil {
			return true
		}
		p, f := event.Packet, r.Packet
		return (f.Protocol == "" || f.Protocol == p.Protocol) &&
			(f.Direction == "" || f.Direction == p.Direction) &&
			packetIPMatches(f.SourceIP, p.SourceIP) &&
			packetIPMatches(f.DestinationIP, p.DestinationIP) &&
			(f.SourcePort == 0 || f.SourcePort == p.SourcePort) &&
			(f.DestinationPort == 0 || f.DestinationPort == p.DestinationPort)
	}
	if event.Packet != nil || event.Process != nil || event.Disk != nil || event.Tracepoint != nil {
		return false
	}
	if r.PID != 0 && r.PID != event.PID {
		return false
	}
	if len(r.Syscalls) == 0 {
		return true
	}
	for _, id := range r.Syscalls {
		if id == event.Syscall {
			return true
		}
	}
	return false
}

func processNameMatches(pattern, name string) bool {
	if pattern == "" {
		return true
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(name, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, pattern[:len(pattern)-1])
	}
	return pattern == name
}

func validEdgeGlob(pattern string) bool {
	return !strings.Contains(pattern, "*") ||
		(strings.Count(pattern, "*") == 1 && len(pattern) > 1 &&
			(pattern[0] == '*' || pattern[len(pattern)-1] == '*'))
}

func packetIPMatches(filter, actual string) bool {
	if filter == "" {
		return true
	}
	ip, err := netip.ParseAddr(filter)
	return err == nil && ip.String() == actual
}

// Monitor streams matching events until ctx is canceled. Callback errors stop
// the subscription. A remote source failure is returned as an error.
func (c Client) Monitor(ctx context.Context, request MonitorRequest, onEvent func(Event) error) error {
	if request.Mode != "" {
		return errors.New("use Client.Query for query modes")
	}
	if err := request.validate(); err != nil {
		return err
	}
	if onEvent == nil {
		return errors.New("event callback required")
	}
	_, err := withClient(c, ctx, func(ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert *ssh.Certificate) (struct{}, error) {
		return struct{}{}, monitorRemote(ctx, ep, reg, signer, cert, request, onEvent)
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
	if err := request.validate(); err != nil {
		return Snapshot{}, err
	}
	return withClient(c, ctx, func(ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert *ssh.Certificate) (Snapshot, error) {
		return monitorRequestRemote(ctx, ep, reg, signer, cert, request, nil)
	})
}

func monitorRemote(ctx context.Context, ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert *ssh.Certificate, request MonitorRequest, onEvent func(Event) error) error {
	_, err := monitorRequestRemote(ctx, ep, reg, signer, cert, request, onEvent)
	return err
}

func monitorRequestRemote(ctx context.Context, ep *iroh.Endpoint, reg registration, signer ssh.Signer, cert *ssh.Certificate, request MonitorRequest, onEvent func(Event) error) (Snapshot, error) {
	id, err := key.ParseEndpointID(reg.EndpointID)
	if err != nil {
		return Snapshot{}, err
	}
	relayURL, err := netaddr.ParseRelayURL(reg.RelayURL)
	if err != nil || relayURL.URL().Host == "" {
		return Snapshot{}, errors.New("invalid relay URL in inventory")
	}
	conn, err := ep.Connect(ctx, netaddr.NewEndpointAddr(id).WithRelayURL(relayURL), alpn)
	if err != nil {
		return Snapshot{}, err
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.Close() })
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

func handleMonitor(ctx context.Context, stream *iroh.Stream, ca ssh.PublicKey, principal string, policy policy, source eventSource) {
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
	cert, err := verifyMonitor(ca, principal, nonce, req)
	if err != nil {
		writeMonitorError(stream, "authentication failed")
		return
	}
	if err := authorizeMonitorSource(policy, cert, req.Source); err != nil {
		writeMonitorError(stream, err.Error())
		return
	}
	if err := req.MonitorRequest.validate(); err != nil {
		writeMonitorError(stream, err.Error())
		return
	}
	if req.Mode == "snapshot" {
		stream.SetDeadline(time.Now().Add(30 * time.Second))
		snapshot, err := querySnapshot(ctx, req.MonitorRequest)
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
		result, err := aggregateEvents(monitorCtx, req.MonitorRequest, source)
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
	var lastTimestamp time.Time
	err = source(monitorCtx, req.MonitorRequest, func(event Event) error {
		if !req.MonitorRequest.matches(event) {
			return nil
		}
		stampEvent(&event, &lastTimestamp)
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
