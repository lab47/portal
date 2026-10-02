package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/relayserver"
)

func TestMonitorProofAndFilters(t *testing.T) {
	ca, signer := testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	nonce := []byte(strings.Repeat("n", 32))
	request := MonitorRequest{Source: "syscalls", PID: 42, Syscalls: []int{3, 9}}
	req, err := signMonitor(signer, cert, nonce, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, req); err != nil {
		t.Fatal(err)
	}
	for _, modified := range []monitorRequest{
		{Certificate: req.Certificate, Signature: req.Signature, MonitorRequest: MonitorRequest{Source: "syscalls", PID: 43, Syscalls: []int{3, 9}}},
		{Certificate: req.Certificate, Signature: req.Signature, MonitorRequest: MonitorRequest{Source: "syscalls", PID: 42, Syscalls: []int{3, 10}}},
	} {
		if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, modified); err == nil {
			t.Fatal("modified monitor request passed signature check")
		}
	}
	if _, err := verifyMonitor(ca.PublicKey(), "admin", []byte(strings.Repeat("x", 32)), req); err == nil {
		t.Fatal("replayed monitor proof accepted")
	}
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, monitorRequest{Certificate: req.Certificate, Signature: req.Signature, MonitorRequest: request}); err != nil {
		t.Fatal(err)
	}
	snapshotReq, err := signMonitor(signer, cert, nonce, MonitorRequest{Source: "process", Mode: "snapshot", PID: 42})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, snapshotReq); err != nil {
		t.Fatal(err)
	}
	snapshotReq.Mode = ""
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, snapshotReq); err == nil {
		t.Fatal("snapshot mode could be changed without invalidating signature")
	}
	networkReq, err := signMonitor(signer, cert, nonce, MonitorRequest{Source: "network", Mode: "snapshot", Name: "eth*"})
	if err != nil {
		t.Fatal(err)
	}
	networkReq.Name = "lo*"
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, networkReq); err == nil {
		t.Fatal("snapshot name filter could be changed without invalidating signature")
	}
	for _, tc := range []struct {
		event Event
		want  bool
	}{
		{Event{PID: 42, Syscall: 9}, true},
		{Event{PID: 43, Syscall: 9}, false},
		{Event{PID: 42, Syscall: 8}, false},
	} {
		if got := request.matches(tc.event); got != tc.want {
			t.Fatalf("matches(%+v) = %v, want %v", tc.event, got, tc.want)
		}
	}
	for _, bad := range []MonitorRequest{
		{Source: "other"}, {Source: "syscalls", Syscalls: []int{-1}}, {Source: "syscalls", Syscalls: []int{65536}},
		{Source: "packets", Mode: "snapshot"}, {Source: "syscalls", Mode: "snapshot"}, {Source: "disk", Mode: "snapshot"},
		{Source: "process", Mode: "unknown"}, {Source: "process", Mode: "snapshot", Process: &ProcessFilter{Action: "start"}},
		{Source: "network", Mode: "snapshot", PID: 1}, {Source: "gpu", Mode: "snapshot", Name: "*"},
	} {
		if err := bad.validate(); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestMonitorStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	relayHTTP := httptest.NewServer(relayserver.New())
	defer relayHTTP.Close()
	relayURL, err := netaddr.ParseRelayURL(relayHTTP.URL)
	if err != nil {
		t.Fatal(err)
	}
	mode := relay.ModeCustomURLs(relayURL)
	server, err := iroh.Bind(ctx, iroh.WithALPNs(alpn), iroh.WithRelayMode(mode), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	if err := server.Online(ctx); err != nil {
		t.Fatal(err)
	}
	client, err := iroh.Bind(ctx, iroh.WithRelayMode(mode), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(context.Background())
	if err := client.Online(ctx); err != nil {
		t.Fatal(err)
	}
	reg := registration{EndpointID: server.ID().String(), RelayURL: relayURL.String()}
	ca, signer := testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	allowed := policy{"operator": {fmt.Sprint(os.Geteuid()): true}}
	stopped := make(chan struct{}, 1)
	source := func(ctx context.Context, request MonitorRequest, emit func(Event) error) error {
		if request.PID == 99 || request.Source == "packets" || request.Source == "disk" {
			return errors.New("eBPF unavailable")
		}
		defer func() { stopped <- struct{}{} }()
		if request.Source == "tracepoint" {
			for _, cpu := range []json.Number{"1", "2"} {
				if err := emit(Event{Time: time.Now().UTC(), Tracepoint: &TracepointEvent{Event: "sched:sched_wakeup", Fields: map[string]json.Number{"target_cpu": cpu}}}); err != nil {
					return err
				}
			}
			<-ctx.Done()
			return nil
		}
		events := []Event{
			{PID: 72, Syscall: 3}, {PID: 71, Syscall: 8}, {PID: 71, Syscall: 3}, {PID: 71, Syscall: 3},
		}
		if request.Source == "process" {
			events = []Event{
				{PID: 72, Process: &ProcessEvent{Name: "worker", Action: "start"}},
				{PID: 71, Process: &ProcessEvent{Name: "worker", Action: "exit"}},
				{PID: 71, Process: &ProcessEvent{Name: "worker", Action: "start"}},
			}
		}
		for _, event := range events {
			if err := emit(event); err != nil {
				return err
			}
		}
		<-ctx.Done()
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- serveWithSource(ctx, server, ca.PublicKey(), "admin", allowed, source) }()
	request := MonitorRequest{Source: "syscalls", PID: 71, Syscalls: []int{3}}
	stopEvent := errors.New("stop after matching event")
	count := 0
	err = monitorRemote(ctx, client, reg, signer, cert, request, func(event Event) error {
		count++
		if err := validateTAI64N(event.TAI64N); err != nil {
			t.Errorf("event missing TAI64N timestamp: %v", err)
		}
		if event.PID != 71 || event.Syscall != 3 {
			t.Errorf("unfiltered event: %+v", event)
		}
		return stopEvent
	})
	if !errors.Is(err, stopEvent) || count != 1 {
		t.Fatalf("stream: %d events, %v", count, err)
	}
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("source was not canceled after client disconnect")
	}
	processRequest, err := ParseMonitorQuery("process where pid = 71 and name = worker and action = start")
	if err != nil {
		t.Fatal(err)
	}
	count = 0
	err = monitorRemote(ctx, client, reg, signer, cert, processRequest, func(event Event) error {
		count++
		if event.PID != 71 || event.Process == nil || event.Process.Action != "start" {
			t.Errorf("unfiltered process event: %+v", event)
		}
		return stopEvent
	})
	if !errors.Is(err, stopEvent) || count != 1 {
		t.Fatalf("process stream: %d events, %v", count, err)
	}
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("process source was not canceled after client disconnect")
	}
	aggregateRequest, err := ParseMonitorQuery("syscalls where syscall = 3 count over 50ms by pid")
	if err != nil {
		t.Fatal(err)
	}
	aggregated, err := monitorRequestRemote(ctx, client, reg, signer, cert, aggregateRequest, nil)
	if err != nil || aggregated.Aggregation == nil || len(aggregated.Aggregation.Counts) != 2 {
		t.Fatalf("remote aggregation: %+v, %v", aggregated, err)
	}
	counts := aggregated.Aggregation.Counts
	if string(counts[0].Group["pid"]) != "71" || counts[0].Count != 2 || string(counts[1].Group["pid"]) != "72" || counts[1].Count != 1 {
		t.Fatalf("remote aggregation lost filters or counts: %+v", counts)
	}
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("aggregation did not stop its source")
	}
	for _, tc := range []struct{ metric, want string }{{"sum(syscall)", "9"}, {"count_distinct(pid)", "2"}, {"percentile(pid,95)", "72"}} {
		request, err := ParseMonitorQuery("syscalls where syscall = 3 " + tc.metric + " over 50ms")
		if err != nil {
			t.Fatal(err)
		}
		got, err := monitorRequestRemote(ctx, client, reg, signer, cert, request, nil)
		if err != nil || got.Aggregation == nil || len(got.Aggregation.Values) != 1 || string(got.Aggregation.Values[0].Value) != tc.want {
			t.Fatalf("remote %s: %+v, %v", tc.metric, got.Aggregation, err)
		}
		select {
		case <-stopped:
		case <-ctx.Done():
			t.Fatal("aggregation source was not canceled")
		}
	}
	for _, tc := range []struct {
		query string
		every time.Duration
	}{
		{"memory avg(total) over 1s", time.Second},
		{fmt.Sprintf("process where pid = %d count_distinct(pid) over 300ms every 100ms", os.Getpid()), 100 * time.Millisecond},
		{fmt.Sprintf("process where pid = %d avg(rss_bytes) over 300ms every 100ms", os.Getpid()), 100 * time.Millisecond},
		{fmt.Sprintf("process where pid = %d avg(cpu_percent) over 500ms every 100ms", os.Getpid()), 100 * time.Millisecond},
	} {
		request, err := ParseMonitorQuery(tc.query)
		if err != nil {
			t.Fatal(err)
		}
		got, err := monitorRequestRemote(ctx, client, reg, signer, cert, request, nil)
		if err != nil || got.Aggregation == nil || len(got.Aggregation.Values) != 1 || got.Aggregation.Every != tc.every {
			t.Fatalf("remote sampled query %s: %+v, %v", tc.query, got.Aggregation, err)
		}
		var value float64
		if err := json.Unmarshal(got.Aggregation.Values[0].Value, &value); err != nil || string(got.Aggregation.Values[0].Value) == "null" || value < 0 || value == 0 && request.Aggregation.Field != "cpu_percent" {
			t.Fatalf("missing sampled value: %s, %v", got.Aggregation.Values[0].Value, err)
		}
		if request.Aggregation.Function == "count_distinct" && value != 1 {
			t.Fatalf("sampled process query lost PID filter: %s", got.Aggregation.Values[0].Value)
		}
	}
	aggregateProof, err := signMonitor(signer, cert, []byte(strings.Repeat("a", 32)), aggregateRequest)
	if err != nil {
		t.Fatal(err)
	}
	aggregateProof.Aggregation = &AggregationRequest{Window: time.Hour, GroupBy: []string{"tid"}}
	if _, err := verifyMonitor(ca.PublicKey(), "admin", []byte(strings.Repeat("a", 32)), aggregateProof); err == nil {
		t.Fatal("aggregation parameters could be changed without invalidating signature")
	}
	numericRequest, err := ParseMonitorQuery("syscalls percentile(pid,95) over 1s")
	if err != nil {
		t.Fatal(err)
	}
	for _, modified := range []AggregationRequest{
		{Window: time.Second, Function: "max", Field: "pid"},
		{Window: time.Second, Function: "percentile", Field: "tid", Percentile: 95},
		{Window: time.Second, Function: "percentile", Field: "pid", Percentile: 99},
	} {
		proof, err := signMonitor(signer, cert, []byte(strings.Repeat("a", 32)), numericRequest)
		if err != nil {
			t.Fatal(err)
		}
		proof.Aggregation = &modified
		if _, err := verifyMonitor(ca.PublicKey(), "admin", []byte(strings.Repeat("a", 32)), proof); err == nil {
			t.Fatal("numeric aggregation parameters were not signed")
		}
	}
	current, err := snapshotProcesses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	self := current[uint32(os.Getpid())]
	if self.name == "" {
		t.Fatal("current test process not visible")
	}
	snapshotRequest := MonitorRequest{Source: "process", Mode: "snapshot", PID: uint32(os.Getpid()), Process: &ProcessFilter{Name: self.name}}
	snapshot, err := monitorRequestRemote(ctx, client, reg, signer, cert, snapshotRequest, nil)
	if err != nil || len(snapshot.Processes) != 1 || snapshot.Processes[0].PID != uint32(os.Getpid()) || snapshot.Processes[0].Name != self.name || snapshot.Processes[0].Started.IsZero() || snapshot.Time.IsZero() {
		t.Fatalf("filtered snapshot: %+v, %v", snapshot, err)
	}
	snapshotRequest.Process.Name = "no-such-process-name-xyz"
	snapshot, err = monitorRequestRemote(ctx, client, reg, signer, cert, snapshotRequest, nil)
	if err != nil || snapshot.Processes == nil || len(snapshot.Processes) != 0 {
		t.Fatalf("empty snapshot: %+v, %v", snapshot, err)
	}
	snapshotRequest.Process.Name = self.name
	for _, source := range []string{"memory", "network", "cpu", "kernel"} {
		got, err := monitorRequestRemote(ctx, client, reg, signer, cert, MonitorRequest{Source: source, Mode: "snapshot"}, nil)
		if err != nil || got.Source != source || got.Time.IsZero() {
			t.Fatalf("%s remote snapshot: %+v, %v", source, got, err)
		}
		if source == "network" && len(got.Network) == 0 || source == "memory" && got.Memory == nil || source == "cpu" && len(got.CPU) == 0 || source == "kernel" && got.Kernel == nil {
			t.Fatalf("%s snapshot lost its data: %+v", source, got)
		}
	}
	if err := monitorRemote(ctx, client, reg, signer, cert, MonitorRequest{Source: "syscalls", PID: 99}, func(Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "eBPF unavailable") {
		t.Fatalf("source error not delivered: %v", err)
	}
	packetRequest := MonitorRequest{Source: "packets", Packet: &PacketFilter{Protocol: "tcp", Direction: "outgoing", DestinationPort: 80}}
	diskRequest := MonitorRequest{Source: "disk", Disk: &DiskFilter{Device: 17, Operation: "write"}}
	traceRequest, err := ParseMonitorQuery("tracepoint where event = sched:sched_wakeup and fields in (target_cpu) and field.target_cpu = 2")
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte(strings.Repeat("d", 32))
	diskProof, err := signMonitor(signer, cert, nonce, diskRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, diskProof); err != nil {
		t.Fatal(err)
	}
	diskProof.Disk = &DiskFilter{Device: 17, Operation: "read"}
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, diskProof); err == nil {
		t.Fatal("modified disk filter passed signature check")
	}
	traceProof, err := signMonitor(signer, cert, nonce, traceRequest)
	if err != nil {
		t.Fatal(err)
	}
	traceProof.Tracepoint = &TracepointFilter{Event: "sched:sched_switch", Fields: []string{"target_cpu"}, Equals: map[string]string{"target_cpu": "2"}}
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, traceProof); err == nil {
		t.Fatal("modified tracepoint probe passed signature check")
	}
	if os.Geteuid() != 0 {
		if err := monitorRemote(ctx, client, reg, signer, cert, traceRequest, func(Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "root server") {
			t.Fatalf("unprivileged tracepoint allowed: %v", err)
		}
		if _, err := monitorRequestRemote(ctx, client, reg, signer, cert, MonitorRequest{Source: "containers", Mode: "snapshot"}, nil); err == nil || !strings.Contains(err.Error(), "root server") {
			t.Fatalf("unprivileged Docker inventory allowed: %v", err)
		}
		if _, err := monitorRequestRemote(ctx, client, reg, signer, cert, MonitorRequest{Source: "cgroups", Mode: "snapshot", Path: "/"}, nil); err == nil || !strings.Contains(err.Error(), "root server") {
			t.Fatalf("unprivileged cgroup inventory allowed: %v", err)
		}
		if err := monitorRemote(ctx, client, reg, signer, cert, packetRequest, func(Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "root server") {
			t.Fatalf("unprivileged packet capture allowed: %v", err)
		}
		if err := monitorRemote(ctx, client, reg, signer, cert, diskRequest, func(Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "root server") {
			t.Fatalf("unprivileged disk monitor allowed: %v", err)
		}
	} else {
		// The identity has explicit root access on this test server.
		if _, err := readCgroups(ctx, "/"); err == nil {
			for _, query := range []string{"cgroups where path = /", "cgroups where path = / avg(cpu_percent) over 300ms every 100ms by path"} {
				r, err := ParseMonitorQuery(query)
				if err != nil {
					t.Fatal(err)
				}
				got, err := monitorRequestRemote(ctx, client, reg, signer, cert, r, nil)
				if err != nil || got.Source != "cgroups" {
					t.Fatalf("remote cgroup query: %+v, %v", got, err)
				}
				if r.Mode == "snapshot" && (len(got.Cgroups) != 1 || got.Cgroups[0].Path != "/" || got.Cgroups[0].CPUSeconds == nil) {
					t.Fatalf("remote cgroup snapshot lost selection or metrics: %+v", got.Cgroups)
				}
				if r.Mode == "aggregate" && (got.Aggregation == nil || len(got.Aggregation.Values) != 1 || string(got.Aggregation.Values[0].Value) == "null") {
					t.Fatalf("remote cgroup aggregation missing: %+v", got.Aggregation)
				}
			}
		}
		seen := 0
		err := monitorRemote(ctx, client, reg, signer, cert, traceRequest, func(event Event) error {
			seen++
			if event.Tracepoint == nil || event.Tracepoint.Fields["target_cpu"] != "2" {
				t.Errorf("unfiltered tracepoint event: %+v", event)
			}
			return stopEvent
		})
		if !errors.Is(err, stopEvent) || seen != 1 {
			t.Fatalf("tracepoint stream: %d events, %v", seen, err)
		}
		select {
		case <-stopped:
		case <-ctx.Done():
			t.Fatal("tracepoint source was not canceled")
		}
		if err := monitorRemote(ctx, client, reg, signer, cert, packetRequest, func(Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "eBPF unavailable") {
			t.Fatalf("authorized packet source did not start: %v", err)
		}
		if err := monitorRemote(ctx, client, reg, signer, cert, diskRequest, func(Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "eBPF unavailable") {
			t.Fatalf("authorized disk source did not start: %v", err)
		}
	}
	otherCert := testCertificate(t, signer, ca, "other", "admin", time.Now().Add(time.Hour))
	if _, err := monitorRequestRemote(ctx, client, reg, signer, otherCert, snapshotRequest, nil); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("unauthorized snapshot: %v", err)
	}
	if err := monitorRemote(ctx, client, reg, signer, otherCert, request, func(Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("unauthorized stream: %v", err)
	}
	if err := monitorRemote(ctx, client, reg, testSigner(t), cert, request, func(Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("bad signature stream: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
