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
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/relayserver"
)

func TestRegisteredMonitorTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stopped := make(chan struct{}, maxRegisteredMonitors)
		store := newMonitorStore(ctx, func(ctx context.Context, _ MonitorRequest, _ func(Event) error) error {
			<-ctx.Done()
			stopped <- struct{}{}
			return nil
		})
		request := MonitorRequest{Source: "process"}
		id, err := store.create("owner", request)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := store.get(id, "owner")
		if m.ttl != 15*time.Minute {
			t.Fatalf("default TTL: %v", m.ttl)
		}
		if _, err := store.create("owner", request, -time.Second); err == nil {
			t.Fatal("negative TTL accepted")
		}
		if _, err := (Client{}).CreateMonitor(ctx, request, time.Second, time.Second); err == nil {
			t.Fatal("multiple TTLs accepted")
		}
		id, err = store.create("owner", request, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		m, _ = store.get(id, "owner")
		time.Sleep(45 * time.Second)
		// Producing events and unauthorized reads must not renew the timer.
		if err := m.append(Event{Process: &ProcessEvent{Name: "worker"}}); err != nil {
			t.Fatal(err)
		}
		if err := store.read(ctx, id, "stranger", 0, "", func(MonitorRecord) error { return nil }); err == nil {
			t.Fatal("stranger read monitor")
		}
		time.Sleep(16 * time.Second)
		synctest.Wait()
		if _, err := store.get(id, "owner"); err == nil {
			t.Fatal("unused monitor did not expire")
		}
		select {
		case <-stopped:
		default:
			t.Fatal("expiry did not cancel the source")
		}
		store.mu.Lock()
		remaining := len(store.byID)
		store.mu.Unlock()
		if remaining != 1 {
			t.Fatalf("expiry did not release registration: %d", remaining)
		}
	})
}

func TestRegisteredMonitorTTLReadRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		store := newMonitorStore(ctx, func(ctx context.Context, _ MonitorRequest, _ func(Event) error) error {
			<-ctx.Done()
			return nil
		})
		id, err := store.create("owner", MonitorRequest{Source: "process"}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := store.get(id, "owner")
		if err := m.append(Event{Process: &ProcessEvent{Name: "worker"}}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(45 * time.Second)
		stop := errors.New("disconnect")
		if err := store.read(ctx, id, "owner", 0, "", func(MonitorRecord) error { return stop }); !errors.Is(err, stop) {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second) // Beyond original TTL, within the renewed TTL.
		if _, err := store.get(id, "owner"); err != nil {
			t.Fatalf("read did not renew TTL: %v", err)
		}
		// Two quiet streaming readers pin the monitor, for either cursor mode.
		readCtx1, cancel1 := context.WithCancel(ctx)
		readCtx2, cancel2 := context.WithCancel(ctx)
		go store.read(readCtx1, id, "owner", 1, "", func(MonitorRecord) error { return nil })
		go store.read(readCtx2, id, "owner", 0, "@ffffffffffffffff00000000", func(MonitorRecord) error { return nil })
		synctest.Wait()
		time.Sleep(2 * time.Minute)
		cancel1()
		synctest.Wait()
		time.Sleep(2 * time.Minute)
		if _, err := store.get(id, "owner"); err != nil {
			t.Fatalf("active quiet read expired: %v", err)
		}
		cancel2()
		synctest.Wait()
		time.Sleep(59 * time.Second)
		if _, err := store.get(id, "owner"); err != nil {
			t.Fatalf("TTL did not restart after last reader: %v", err)
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if _, err := store.get(id, "owner"); err == nil {
			t.Fatal("disconnected monitor did not expire")
		}
	})
}

func TestRegisteredMonitorTTLAfterSourceFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		store := newMonitorStore(ctx, func(context.Context, MonitorRequest, func(Event) error) error {
			return errors.New("source failed")
		})
		id, err := store.create("owner", MonitorRequest{Source: "process"}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(45 * time.Second)
		if err := store.read(ctx, id, "owner", 0, "", func(MonitorRecord) error { return nil }); err == nil || err.Error() != "source failed" {
			t.Fatalf("failed source not readable: %v", err)
		}
		time.Sleep(59 * time.Second)
		if _, err := store.get(id, "owner"); err != nil {
			t.Fatalf("error read did not renew TTL: %v", err)
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if _, err := store.get(id, "owner"); err == nil {
			t.Fatal("failed source retained forever")
		}
	})
}

func TestRegisteredMonitorRingCursors(t *testing.T) {
	m := &registeredMonitor{request: MonitorRequest{Source: "syscalls"}, next: 1, wake: make(chan struct{})}
	for i := 1; i <= monitorRingSize+1; i++ {
		if err := m.append(Event{PID: uint32(i), Time: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	if err := m.read(ctx, 0, "", func(MonitorRecord) error { t.Fatal("silently skipped lost history"); return nil }); err == nil || !strings.Contains(err.Error(), "oldest available sequence is 2") {
		t.Fatalf("overflow did not report gap: %v", err)
	}
	stop := errors.New("stop")
	var got MonitorRecord
	if err := m.read(ctx, 1, "", func(record MonitorRecord) error { got = record; return stop }); !errors.Is(err, stop) || got.Sequence != 2 || got.Event.PID != 2 {
		t.Fatalf("oldest retained event: %+v, %v", got, err)
	}
	if err := m.read(ctx, monitorRingSize+2, "", func(MonitorRecord) error { return nil }); err == nil || !strings.Contains(err.Error(), "ahead") {
		t.Fatalf("accepted future cursor: %v", err)
	}
	if err := m.append(Event{PID: 1, Syscall: 3}); err != nil {
		t.Fatal(err)
	}
	m.finish(errors.New("source failed"))
	var sequences []uint64
	err := m.read(ctx, monitorRingSize, "", func(record MonitorRecord) error {
		sequences = append(sequences, record.Sequence)
		return nil
	})
	if err == nil || err.Error() != "source failed" || len(sequences) != 2 || sequences[0] != monitorRingSize+1 || sequences[1] != monitorRingSize+2 {
		t.Fatalf("source error before buffered records: %v, %v", sequences, err)
	}
}

func TestRegisteredMonitorTimestampResume(t *testing.T) {
	m := &registeredMonitor{next: 4, wake: make(chan struct{}), done: true, err: errors.New("finished")}
	for i := uint64(1); i <= 3; i++ {
		stamp := fmt.Sprintf("@4000000000000000%08x", i*10)
		data, err := json.Marshal(Event{PID: uint32(i), TAI64N: stamp})
		if err != nil {
			t.Fatal(err)
		}
		m.ring[i-1] = monitorRingEntry{data: data, timestamp: stamp}
	}
	for _, tc := range []struct {
		nanos uint32
		want  uint64
	}{{0, 1}, {10, 2}, {15, 2}, {29, 3}, {30, 0}, {40, 0}} {
		var got MonitorRecord
		err := m.read(context.Background(), 0, fmt.Sprintf("@4000000000000000%08x", tc.nanos), func(record MonitorRecord) error {
			got = record
			return errors.New("stop")
		})
		if err == nil || got.Sequence != tc.want || (tc.want != 0 && got.Event.PID != uint32(tc.want)) {
			t.Fatalf("resume after %d ns: %+v, %v; want %d", tc.nanos, got, err, tc.want)
		}
	}
	// An old timestamp clamps to the oldest retained record after wraparound.
	m.next = monitorRingSize + 3
	stamp := "@40000000000000000000001e"
	data, err := json.Marshal(Event{PID: 3, TAI64N: stamp})
	if err != nil {
		t.Fatal(err)
	}
	m.ring[2] = monitorRingEntry{data: data, timestamp: stamp}
	var got MonitorRecord
	_ = m.read(context.Background(), 0, "@400000000000000000000000", func(record MonitorRecord) error { got = record; return errors.New("stop") })
	if got.Sequence != 3 || got.Event.PID != 3 {
		t.Fatalf("old timestamp did not clamp to retained history: %+v", got)
	}
}

func TestRegisteredMonitorWaitAndLimits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store := newMonitorStore(ctx, func(ctx context.Context, _ MonitorRequest, _ func(Event) error) error {
		<-ctx.Done()
		return nil
	})
	var id string
	for i := 0; i < maxRegisteredMonitors; i++ {
		var err error
		id, err = store.create("owner", MonitorRequest{Source: "process"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.create("owner", MonitorRequest{Source: "process"}); err == nil {
		t.Fatal("registered monitor cap not enforced")
	}
	if err := store.delete(id, "stranger"); err == nil {
		t.Fatal("stranger deleted a monitor")
	}
	m, err := store.get(id, "owner")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.read(ctx, 0, "", func(MonitorRecord) error { return nil }) }()
	if err := store.delete(id, "owner"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "deleted") {
			t.Fatalf("blocked reader not notified of delete: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("delete left reader blocked")
	}
	if _, err := store.create("owner", MonitorRequest{Source: "process"}); err != nil {
		t.Fatalf("delete did not free capacity: %v", err)
	}
	if _, err := store.create("owner", MonitorRequest{Source: "process", Mode: "snapshot"}); err == nil || !strings.Contains(err.Error(), "event mode") {
		t.Fatalf("accepted snapshot registration: %v", err)
	}
}

func TestRegisteredMonitorFollowsAndReplays(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m := &registeredMonitor{request: MonitorRequest{Source: "syscalls"}, next: 1, wake: make(chan struct{})}
	if err := m.append(Event{PID: 42, Syscall: 3}); err != nil {
		t.Fatal(err)
	}
	firstRead := make(chan struct{})
	done := make(chan error, 1)
	stop := errors.New("stop")
	go func() {
		done <- m.read(ctx, 0, "", func(record MonitorRecord) error {
			if record.Sequence == 1 {
				close(firstRead)
				return nil
			}
			if record.Sequence != 2 || record.Event.Syscall != 4 {
				return fmt.Errorf("unexpected live record: %+v", record)
			}
			return stop
		})
	}()
	select {
	case <-firstRead:
	case <-ctx.Done():
		t.Fatal("reader did not replay first record")
	}
	if err := m.append(Event{PID: 42, Syscall: 4}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, stop) {
			t.Fatalf("reader did not follow: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("reader lost wakeup")
	}
	// Reading is non-destructive; a second consumer can use its own cursor.
	if err := m.read(ctx, 0, "", func(record MonitorRecord) error {
		if record.Sequence != 1 || record.Event.Syscall != 3 {
			t.Errorf("first record consumed by previous reader: %+v", record)
		}
		return stop
	}); !errors.Is(err, stop) {
		t.Fatal(err)
	}
}

func TestRegisteredMonitorReconnectAndAuthorization(t *testing.T) {
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
	ca, signer, stranger := testSigner(t), testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	otherCert := testCertificate(t, stranger, ca, "operator", "admin", time.Now().Add(time.Hour))
	input := make(chan Event)
	ack := make(chan struct{})
	stopped := make(chan struct{})
	started := make(chan struct{}, 1)
	source := func(ctx context.Context, _ MonitorRequest, emit func(Event) error) error {
		started <- struct{}{}
		defer close(stopped)
		for {
			select {
			case event := <-input:
				if err := emit(event); err != nil {
					return err
				}
				ack <- struct{}{}
			case <-ctx.Done():
				return nil
			}
		}
	}
	done := make(chan error, 1)
	go func() {
		done <- serveWithSource(ctx, server, ca.PublicKey(), "admin", policy{"operator": {fmt.Sprint(os.Geteuid()): true}}, source)
	}()
	request := MonitorRequest{Source: "syscalls", PID: 42}
	id, err := registeredMonitorRemote(ctx, client, reg, signer, cert, monitorAction{Action: "create", Request: &request, TTL: time.Hour}, nil)
	if err != nil || len(id) != 32 {
		t.Fatalf("create: %q, %v", id, err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("source not started")
	}
	send := func(event Event) {
		t.Helper()
		select {
		case input <- event:
		case <-ctx.Done():
			t.Fatal("source stopped")
		}
		select {
		case <-ack:
		case <-ctx.Done():
			t.Fatal("event not retained")
		}
	}
	send(Event{Time: time.Now().UTC(), PID: 7, Syscall: 1}) // not retained
	send(Event{Time: time.Now().UTC(), PID: 42, Syscall: 3})
	stop := errors.New("stop reading")
	var first MonitorRecord
	_, err = registeredMonitorRemote(ctx, client, reg, signer, cert, monitorAction{Action: "read", ID: id}, func(record MonitorRecord) error { first = record; return stop })
	if !errors.Is(err, stop) || first.Sequence != 1 || first.Event.PID != 42 {
		t.Fatalf("first read: %+v, %v", first, err)
	}
	// The source must continue while there is no reader connected.
	send(Event{Time: time.Now().UTC(), PID: 42, Syscall: 4})
	var second MonitorRecord
	if err := validateTAI64N(first.Event.TAI64N); err != nil {
		t.Fatalf("missing event timestamp: %v", err)
	}
	_, err = registeredMonitorRemote(ctx, client, reg, signer, cert, monitorAction{Action: "read", ID: id, AfterTimestamp: first.Event.TAI64N}, func(record MonitorRecord) error { second = record; return stop })
	if !errors.Is(err, stop) || second.Sequence != 2 || second.Event.Syscall != 4 {
		t.Fatalf("resumed read: %+v, %v", second, err)
	}
	if _, err := registeredMonitorRemote(ctx, client, reg, stranger, otherCert, monitorAction{Action: "read", ID: id}, func(MonitorRecord) error { return stop }); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("different key with same policy identity read monitor: %v", err)
	}
	for i := 0; i < monitorRingSize; i++ {
		send(Event{Time: time.Now().UTC(), PID: 42, Syscall: 5})
	}
	_, err = registeredMonitorRemote(ctx, client, reg, signer, cert, monitorAction{Action: "read", ID: id, After: 1}, func(MonitorRecord) error { t.Fatal("silently skipped overwritten records"); return stop })
	var gap *MonitorHistoryLostError
	if !errors.As(err, &gap) || gap.OldestSequence != 3 {
		t.Fatalf("gap not preserved over the wire: %v", err)
	}
	var clamped MonitorRecord
	_, err = registeredMonitorRemote(ctx, client, reg, signer, cert, monitorAction{Action: "read", ID: id, AfterTimestamp: first.Event.TAI64N}, func(record MonitorRecord) error { clamped = record; return stop })
	if !errors.Is(err, stop) || clamped.Sequence != 3 {
		t.Fatalf("timestamp resume did not return closest retained event: %+v, %v", clamped, err)
	}
	if _, err := registeredMonitorRemote(ctx, client, reg, signer, cert, monitorAction{Action: "delete", ID: id}, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("delete did not stop source")
	}
	if _, err := registeredMonitorRemote(ctx, client, reg, signer, cert, monitorAction{Action: "read", ID: id}, func(MonitorRecord) error { return stop }); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("deleted monitor still readable: %v", err)
	}
	nonce := []byte(strings.Repeat("x", 32))
	proof, err := signRegisteredMonitor(signer, cert, nonce, monitorAction{Action: "read", ID: id, After: 1})
	if err != nil {
		t.Fatal(err)
	}
	proof.After = 0
	if _, err := verifyRegisteredMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
		t.Fatal("modified cursor passed signature check")
	}
	proof, err = signRegisteredMonitor(signer, cert, nonce, monitorAction{Action: "read", ID: id, AfterTimestamp: first.Event.TAI64N})
	if err != nil {
		t.Fatal(err)
	}
	proof.AfterTimestamp = second.Event.TAI64N
	if _, err := verifyRegisteredMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
		t.Fatal("modified timestamp passed signature check")
	}
	proof, err = signRegisteredMonitor(signer, cert, nonce, monitorAction{Action: "create", Request: &request, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	proof.TTL = time.Hour
	if _, err := verifyRegisteredMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
		t.Fatal("modified TTL passed signature check")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
