package portal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
)

const monitorRingSize = 1024
const maxRegisteredMonitors = 16
const maxMonitorEventSize = 8 << 10

// DefaultMonitorTTL is the idle lifetime of a registered monitor.
const DefaultMonitorTTL = 15 * time.Minute

// MonitorRecord carries a per-registration sequence number. Save Sequence only
// after processing the event, then pass it as after to the next ReadMonitor.
type MonitorRecord struct {
	Sequence uint64 `json:"sequence"`
	Event    Event  `json:"event"`
}

// MonitorHistoryLostError reports overwritten events. To explicitly skip the
// lost history, resume with after=OldestSequence-1.
type MonitorHistoryLostError struct {
	OldestSequence uint64
}

func (e *MonitorHistoryLostError) Error() string {
	return fmt.Sprintf("monitor history lost: oldest available sequence is %d", e.OldestSequence)
}

type registeredMonitor struct {
	owner         string
	request       MonitorRequest
	cancel        context.CancelFunc
	mu            sync.Mutex
	ring          [monitorRingSize]monitorRingEntry
	lastTimestamp time.Time
	next          uint64 // next sequence to assign; starts at 1
	wake          chan struct{}
	err           error
	done          bool
	// Lifetime fields are protected by monitorStore.mu, not mu.
	ttl       time.Duration
	expiresAt time.Time
	readers   int
	timer     *time.Timer
}

type monitorRingEntry struct {
	data      json.RawMessage
	timestamp string
}

func (m *registeredMonitor) notify() {
	close(m.wake)
	m.wake = make(chan struct{})
}

func (m *registeredMonitor) append(event Event) error {
	if !m.request.matches(event) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done {
		return errors.New("monitor stopped")
	}
	stampEvent(&event, &m.lastTimestamp)
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(data) > maxMonitorEventSize {
		return errors.New("monitor event exceeds ring entry limit")
	}
	m.ring[(m.next-1)%monitorRingSize] = monitorRingEntry{data: data, timestamp: event.TAI64N}
	m.next++
	m.notify()
	return nil
}

func (m *registeredMonitor) finish(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.done {
		m.err = err
		m.done = true
		m.notify()
	}
}

func (m *registeredMonitor) read(ctx context.Context, after uint64, timestamp string, deliver func(MonitorRecord) error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m.mu.Lock()
		oldest := uint64(1)
		if m.next > monitorRingSize+1 {
			oldest = m.next - monitorRingSize
		}
		if after < oldest-1 {
			if timestamp != "" {
				after = oldest - 1 // Best-effort timestamp resumes clamp to retained history.
			} else {
				m.mu.Unlock()
				return &MonitorHistoryLostError{OldestSequence: oldest}
			}
		}
		if after >= m.next {
			m.mu.Unlock()
			return errors.New("monitor cursor is ahead of the latest event")
		}
		if after+1 < m.next {
			sequence := after + 1
			data := m.ring[(sequence-1)%monitorRingSize]
			m.mu.Unlock()
			if timestamp != "" && data.timestamp <= timestamp {
				after = sequence
				continue
			}
			var event Event
			if err := json.Unmarshal(data.data, &event); err != nil {
				return err
			}
			if err := deliver(MonitorRecord{Sequence: sequence, Event: event}); err != nil {
				return err
			}
			after = sequence
			timestamp = ""
			continue
		}
		if m.done {
			err := m.err
			m.mu.Unlock()
			if err == nil {
				return errors.New("monitor stopped")
			}
			return err
		}
		wake := m.wake
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		}
	}
}

type monitorStore struct {
	ctx    context.Context
	source eventSource
	mu     sync.Mutex
	byID   map[string]*registeredMonitor
}

func newMonitorStore(ctx context.Context, source eventSource) *monitorStore {
	s := &monitorStore{ctx: ctx, source: source, byID: make(map[string]*registeredMonitor)}
	context.AfterFunc(ctx, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for id, m := range s.byID {
			delete(s.byID, id)
			m.timer.Stop()
			m.finish(ctx.Err())
			m.cancel()
		}
	})
	return s
}

func monitorTTL(ttl []time.Duration) (time.Duration, error) {
	if len(ttl) == 0 || (len(ttl) == 1 && ttl[0] == 0) {
		return DefaultMonitorTTL, nil
	}
	if len(ttl) != 1 || ttl[0] < 0 {
		return 0, errors.New("monitor TTL must be a positive duration")
	}
	return ttl[0], nil
}

func (s *monitorStore) create(owner string, request MonitorRequest, ttl ...time.Duration) (string, error) {
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
	request, err = resolveSyscallNames(request, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return "", errors.New("server stopped")
	}
	if len(s.byID) >= maxRegisteredMonitors {
		return "", errors.New("registered monitor limit reached")
	}
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(bytes[:])
	ctx, cancel := context.WithCancel(s.ctx)
	m := &registeredMonitor{owner: owner, request: request, cancel: cancel, next: 1, wake: make(chan struct{}), ttl: lifetime, expiresAt: time.Now().Add(lifetime)}
	s.byID[id] = m
	m.timer = time.AfterFunc(lifetime, func() { s.expire(id, m) })
	go func() {
		defer cancel()
		err := s.source(ctx, request, m.append)
		m.finish(err)
	}()
	return id, nil
}

func (s *monitorStore) expire(id string, m *registeredMonitor) {
	s.mu.Lock()
	if s.byID[id] != m || m.readers != 0 {
		s.mu.Unlock()
		return
	}
	if remaining := time.Until(m.expiresAt); remaining > 0 {
		m.timer.Reset(remaining)
		s.mu.Unlock()
		return
	}
	delete(s.byID, id)
	s.mu.Unlock()
	m.finish(errors.New("monitor expired"))
	m.cancel()
}

// read pins the registration for the entire stream, including quiet sources.
func (s *monitorStore) read(ctx context.Context, id, owner string, after uint64, timestamp string, deliver func(MonitorRecord) error) error {
	s.mu.Lock()
	m, ok := s.byID[id]
	if !ok || m.owner != owner {
		s.mu.Unlock()
		return errors.New("monitor not found")
	}
	if m.readers == 0 && !time.Now().Before(m.expiresAt) {
		s.mu.Unlock()
		s.expire(id, m)
		return errors.New("monitor not found")
	}
	m.readers++
	m.timer.Stop()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		m.readers--
		if s.byID[id] == m && m.readers == 0 {
			m.expiresAt = time.Now().Add(m.ttl)
			m.timer.Reset(m.ttl)
		}
	}()
	return m.read(ctx, after, timestamp, deliver)
}

func (s *monitorStore) get(id, owner string) (*registeredMonitor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.byID[id]
	if !ok || m.owner != owner {
		return nil, errors.New("monitor not found")
	}
	return m, nil
}

func (s *monitorStore) delete(id, owner string) error {
	s.mu.Lock()
	m, ok := s.byID[id]
	if ok && m.owner == owner {
		delete(s.byID, id)
		m.timer.Stop()
	}
	s.mu.Unlock()
	if !ok || m.owner != owner {
		return errors.New("monitor not found")
	}
	m.finish(errors.New("monitor deleted"))
	m.cancel()
	return nil
}
