package query

import (
	"context"
	"errors"
	"runtime"
	"time"
)

// EventSource supplies raw events for an event-mode request.
type EventSource func(context.Context, MonitorRequest, func(Event) error) error

// SnapshotSource collects one snapshot for a snapshot-mode request.
type SnapshotSource func(context.Context, MonitorRequest) (Snapshot, error)

// Engine executes local queries. Nil sources use the built-in collectors.
type Engine struct {
	Events    EventSource
	Snapshots SnapshotSource
}

func (e Engine) eventSource() EventSource {
	if e.Events != nil {
		return e.Events
	}
	return CollectEvents
}

func (e Engine) snapshotSource() SnapshotSource {
	if e.Snapshots != nil {
		return e.Snapshots
	}
	return querySnapshot
}

// Query normalizes query mode, resolves syscall names for the native ABI, and
// dispatches snapshots, sampled aggregates, and event aggregates.
func (e Engine) Query(ctx context.Context, request MonitorRequest) (Snapshot, error) {
	if request.Mode != "aggregate" {
		request.Mode = "snapshot"
	}
	if request.Aggregation != nil {
		request.Mode = "aggregate"
	}
	if err := request.Validate(); err != nil {
		return Snapshot{}, err
	}
	request, err := ResolveSyscallNames(request, runtime.GOARCH)
	if err != nil {
		return Snapshot{}, err
	}
	if request.Source == "script" {
		return aggregateScript(ctx, request, e.eventSource(), e.snapshotSource())
	}
	if request.Mode == "snapshot" {
		return e.snapshotSource()(ctx, request)
	}
	if sampledAggregation(request) {
		return aggregateSnapshots(ctx, request, e.snapshotSource())
	}
	return aggregateEvents(ctx, request, e.eventSource())
}

// Monitor validates and streams filtered, timestamped events.
func (e Engine) Monitor(ctx context.Context, request MonitorRequest, onEvent func(Event) error) error {
	if request.Mode != "" {
		return errors.New("use Engine.Query for query modes")
	}
	if onEvent == nil {
		return errors.New("event callback required")
	}
	if err := request.Validate(); err != nil {
		return err
	}
	request, err := ResolveSyscallNames(request, runtime.GOARCH)
	if err != nil {
		return err
	}
	var last time.Time
	return e.eventSource()(ctx, request, func(event Event) error {
		if !request.Matches(event) {
			return nil
		}
		StampEvent(&event, &last)
		return onEvent(event)
	})
}
