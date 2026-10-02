package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxAggregateGroups = 4096
const maxAggregateValues = 65536
const maxAggregateMetrics = 8

// AggregateMetric selects one reduction in a shared window and grouping.
type AggregateMetric struct {
	Function   string  `json:"function"`
	Field      string  `json:"field,omitempty"`
	Percentile float64 `json:"percentile,omitempty"`
}

// AggregationRequest reduces matching events or sampled snapshots during a new window.
// An omitted Function selects count for compatibility.
type AggregationRequest struct {
	Window     time.Duration     `json:"window"` // nanoseconds
	GroupBy    []string          `json:"group_by,omitempty"`
	Function   string            `json:"function,omitempty"` // count, sum, avg, min, max, count_distinct, percentile
	Field      string            `json:"field,omitempty"`
	Percentile float64           `json:"percentile,omitempty"` // 0–100, only for percentile
	Every      time.Duration     `json:"every,omitempty"`      // Snapshot sampling interval; zero defaults to 1s for snapshot-only sources.
	Metrics    []AggregateMetric `json:"metrics,omitempty"`    // Alternative to Function/Field/Percentile; all share Window/Every/GroupBy.
}

type AggregateCount struct {
	Group map[string]json.RawMessage `json:"group"`
	Count uint64                     `json:"count"`
}

type AggregateValue struct {
	Group map[string]json.RawMessage `json:"group"`
	Value json.RawMessage            `json:"value"` // JSON number (avg rounded to 18 decimal places), or null
}

// AggregationResult describes a half-open server ingestion window [Start, End).
type AggregationResult struct {
	Start      time.Time            `json:"start"`
	End        time.Time            `json:"end"`
	GroupBy    []string             `json:"group_by"`
	Counts     []AggregateCount     `json:"counts,omitempty"`
	Function   string               `json:"function,omitempty"`
	Field      string               `json:"field,omitempty"`
	Percentile float64              `json:"percentile,omitempty"`
	Values     []AggregateValue     `json:"values,omitempty"`
	Every      time.Duration        `json:"every,omitempty"`
	Collection *CollectionStats     `json:"collection,omitempty"`
	Metrics    []*AggregationResult `json:"metrics,omitempty"` // In request order; each has the same window/grouping. Single queries retain their old shape.
}

// Keep the selected result collection visible even for an empty grouped window.
func (a AggregationResult) MarshalJSON() ([]byte, error) {
	type fields AggregationResult
	if len(a.Metrics) != 0 {
		return json.Marshal(fields(a))
	}
	if a.Function == "" || a.Function == "count" {
		return json.Marshal(struct {
			fields
			Counts []AggregateCount `json:"counts"`
		}{fields(a), a.Counts})
	}
	return json.Marshal(struct {
		fields
		Values []AggregateValue `json:"values"`
	}{fields(a), a.Values})
}

func aggregateFields(r MonitorRequest) (fields, numeric []string, err error) {
	if sampledAggregation(r) {
		fields, numeric = sampledFields(r.Source)
		return
	}
	switch r.Source {
	case "syscalls":
		fields = []string{"pid", "tid", "syscall"}
		numeric = append([]string{}, fields...)
		if r.Phase == "completion" {
			fields = append(fields, "duration_ns", "return_value")
			numeric = append(numeric, "duration_ns", "return_value")
		}
		if r.Paths {
			fields = append(fields, "file.fd", "file.path", "file.error")
			numeric = append(numeric, "file.fd")
		}
	case "process":
		fields = []string{"pid", "name", "action"}
		numeric = []string{"pid"}
	case "packets":
		fields = []string{"protocol", "direction", "src.ip", "dst.ip", "src.port", "dst.port", "length"}
		numeric = []string{"src.port", "dst.port", "length"}
	case "disk":
		fields = []string{"device", "operation", "sector", "sectors"}
		numeric = []string{"device", "sector", "sectors"}
		if r.Phase == "completion" {
			fields = append(fields, "duration_ns", "status")
			numeric = append(numeric, "duration_ns", "status")
		}
	case "tracepoint":
		if r.Tracepoint != nil {
			for _, name := range r.Tracepoint.Fields {
				fields = append(fields, "field."+name)
			}
		}
		numeric = fields
	default:
		err = errors.New("aggregation requires an event source")
	}
	if r.Source == "syscalls" || r.Source == "disk" || r.Source == "tracepoint" {
		if r.Source != "syscalls" {
			fields = append(fields, "pid", "tid")
			numeric = append(append([]string{}, numeric...), "pid", "tid")
		}
		fields = append(fields, "name")
	}
	if r.Stacks != nil {
		if r.Stacks.User {
			fields = append(fields, "user.stack")
		}
		if r.Stacks.Kernel {
			fields = append(fields, "kernel.stack")
		}
	}
	return
}

func (a AggregationRequest) validate(r MonitorRequest) error {
	if len(a.Metrics) != 0 {
		if len(a.Metrics) > maxAggregateMetrics {
			return errors.New("aggregation supports at most 8 metrics")
		}
		if a.Function != "" || a.Field != "" || a.Percentile != 0 {
			return errors.New("metrics cannot be combined with function, field or percentile")
		}
		seen := make(map[AggregateMetric]bool)
		for _, metric := range a.Metrics {
			if metric.Function == "" {
				metric.Function = "count"
			}
			if seen[metric] {
				return errors.New("duplicate aggregate metric")
			}
			seen[metric] = true
			one := a
			one.Metrics = nil
			one.Function, one.Field, one.Percentile = metric.Function, metric.Field, metric.Percentile
			if err := one.validate(r); err != nil {
				return err
			}
		}
		return nil
	}
	if a.Window <= 0 || a.Window > time.Hour {
		return errors.New("aggregation window must be positive and at most 1h")
	}
	if len(a.GroupBy) > 4 {
		return errors.New("aggregation supports at most 4 grouping fields")
	}
	if sampledAggregation(r) {
		interval := a.Every
		if interval == 0 {
			interval = DefaultSampleInterval
		}
		if interval < MinSampleInterval || interval > a.Window {
			return errors.New("sampling interval must be at least 100ms and no greater than the window")
		}
		for _, field := range snapshotSampleFields(r.Source) {
			if (field.Path == a.Field || slices.Contains(a.GroupBy, field.Path)) && (field.Semantics == "rate" || field.Semantics == "utilization") && interval >= a.Window {
				return errors.New("derived metrics require a window longer than the sampling interval")
			}
		}
	} else if a.Every != 0 {
		return errors.New("every requires a snapshot source")
	}
	fields, numeric, err := aggregateFields(r)
	if err != nil {
		return err
	}
	switch a.Function {
	case "", "count":
		if a.Field != "" {
			return errors.New("count does not accept a field")
		}
	case "count_distinct":
		if !slices.Contains(fields, a.Field) {
			return fmt.Errorf("invalid distinct field %q", a.Field)
		}
	case "sum", "avg", "min", "max", "percentile":
		if !slices.Contains(numeric, a.Field) {
			return fmt.Errorf("aggregation requires a numeric gauge or derived field, got %q", a.Field)
		}
	default:
		return fmt.Errorf("unsupported aggregation function %q", a.Function)
	}
	if math.IsNaN(a.Percentile) || math.IsInf(a.Percentile, 0) || a.Percentile < 0 || a.Percentile > 100 || (a.Function != "percentile" && a.Percentile != 0) {
		return errors.New("percentile must be between 0 and 100 and used only with percentile")
	}
	seen := make(map[string]bool)
	for _, field := range a.GroupBy {
		if seen[field] || !slices.Contains(fields, field) {
			return fmt.Errorf("invalid or duplicate aggregation field %q for %s", field, r.Source)
		}
		seen[field] = true
	}
	return nil
}

func eventGroupFields(event Event, stacks *StackCapture) map[string]any {
	var fields map[string]any
	switch {
	case event.Process != nil:
		fields = map[string]any{"pid": event.PID, "name": event.Process.Name, "action": event.Process.Action}
	case event.Packet != nil:
		p := event.Packet
		fields = map[string]any{"protocol": p.Protocol, "direction": p.Direction, "src.ip": p.SourceIP, "dst.ip": p.DestinationIP, "src.port": p.SourcePort, "dst.port": p.DestinationPort, "length": p.Length}
	case event.Disk != nil:
		fields = map[string]any{"device": event.Disk.Device, "operation": event.Disk.Operation, "sector": event.Disk.Sector, "sectors": event.Disk.Sectors}
		if event.Disk.DurationNS != nil {
			fields["duration_ns"] = *event.Disk.DurationNS
		}
		if event.Disk.Status != nil {
			fields["status"] = *event.Disk.Status
		}
	case event.Tracepoint != nil:
		fields = make(map[string]any, len(event.Tracepoint.Fields))
		for name, value := range event.Tracepoint.Fields {
			fields["field."+name] = value
		}
	default:
		fields = map[string]any{"pid": event.PID, "tid": event.TID, "syscall": event.Syscall}
	}
	if event.UserStack != nil {
		var shape *StackShape
		if stacks != nil {
			shape = stacks.UserShape
		}
		fields["user.stack"] = event.UserStack.key(shape)
	}
	if event.KernelStack != nil {
		var shape *StackShape
		if stacks != nil {
			shape = stacks.KernelShape
		}
		fields["kernel.stack"] = event.KernelStack.key(shape)
	}
	if event.Process == nil && event.Packet == nil {
		fields["pid"], fields["tid"], fields["name"] = event.PID, event.TID, event.Name
	}
	if event.DurationNS != nil {
		fields["duration_ns"] = *event.DurationNS
	}
	if event.ReturnValue != nil {
		fields["return_value"] = *event.ReturnValue
	}
	if event.File != nil {
		fields["file.fd"] = event.File.FD
		if event.File.Path != "" {
			fields["file.path"] = event.File.Path
		}
		if event.File.Error != "" {
			fields["file.error"] = event.File.Error
		}
	}
	return fields
}

type aggregateAccumulator struct {
	AggregateCount
	sum      big.Rat
	min, max *big.Rat
	distinct map[string]struct{}
	samples  []*big.Rat
}

func (e *aggregateAccumulator) add(a AggregationRequest, value any, retained *int) error {
	if a.Function == "" || a.Function == "count" {
		e.Count++
		return nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if a.Function == "count_distinct" {
		if e.distinct == nil {
			e.distinct = make(map[string]struct{})
		}
		key := string(data)
		if _, ok := e.distinct[key]; !ok {
			if *retained >= maxAggregateValues {
				return errors.New("aggregation exceeds 65536 retained values")
			}
			e.distinct[key] = struct{}{}
			*retained += 1
		}
	} else {
		n, ok := new(big.Rat).SetString(string(data))
		if !ok {
			return fmt.Errorf("aggregation field %q is not numeric", a.Field)
		}
		switch a.Function {
		case "sum", "avg":
			e.sum.Add(&e.sum, n)
		case "min", "max":
			if e.min == nil || n.Cmp(e.min) < 0 {
				e.min = n
			}
			if e.max == nil || n.Cmp(e.max) > 0 {
				e.max = n
			}
		case "percentile":
			if *retained >= maxAggregateValues {
				return errors.New("aggregation exceeds 65536 retained values")
			}
			e.samples = append(e.samples, n)
			*retained += 1
		}
	}
	e.Count++
	return nil
}

func (e *aggregateAccumulator) value(a AggregationRequest) json.RawMessage {
	number := func(n *big.Rat) string {
		if n.IsInt() {
			return n.Num().String()
		}
		return n.FloatString(18)
	}
	var value string
	switch a.Function {
	case "sum":
		value = number(&e.sum)
	case "count_distinct":
		value = fmt.Sprint(len(e.distinct))
	default:
		if e.Count == 0 {
			return json.RawMessage("null")
		}
		switch a.Function {
		case "avg":
			mean := new(big.Rat).Quo(&e.sum, new(big.Rat).SetInt(new(big.Int).SetUint64(e.Count)))
			value = mean.FloatString(18)
		case "min":
			value = number(e.min)
		case "max":
			value = number(e.max)
		case "percentile":
			slices.SortFunc(e.samples, func(a, b *big.Rat) int { return a.Cmp(b) })
			// Use a decimal rational to avoid floating-point rank errors at boundaries.
			p, _ := new(big.Rat).SetString(fmt.Sprint(a.Percentile))
			p.Mul(p, big.NewRat(int64(len(e.samples)), 100))
			rank, remainder := new(big.Int), new(big.Int)
			rank.QuoRem(p.Num(), p.Denom(), remainder)
			if remainder.Sign() != 0 {
				rank.Add(rank, big.NewInt(1))
			}
			index := max(0, int(rank.Int64())-1)
			value = number(e.samples[index])
		}
	}
	return json.RawMessage(value)
}

// aggregateReduction is shared by event windows and sampled snapshots.
type aggregateReduction struct {
	request  AggregationRequest
	groups   map[string]*aggregateAccumulator
	retained *int // Shared across metrics: the storage cap is per query, not per function.
	metrics  []*aggregateReduction
}

func newAggregateReduction(a AggregationRequest) *aggregateReduction {
	r := &aggregateReduction{request: a, groups: make(map[string]*aggregateAccumulator), retained: new(int)}
	if len(a.Metrics) != 0 {
		for _, metric := range a.Metrics {
			one := a
			one.Metrics = nil
			one.Function, one.Field, one.Percentile = metric.Function, metric.Field, metric.Percentile
			if one.Function == "" {
				one.Function = "count"
			}
			child := newAggregateReduction(one)
			child.retained = r.retained
			r.metrics = append(r.metrics, child)
		}
		return r
	}
	if len(a.GroupBy) == 0 {
		r.groups[""] = &aggregateAccumulator{AggregateCount: AggregateCount{Group: map[string]json.RawMessage{}}}
	}
	return r
}

func (r *aggregateReduction) add(fields map[string]any) error {
	if len(r.metrics) != 0 {
		for _, metric := range r.metrics {
			if err := metric.add(fields); err != nil {
				return err
			}
		}
		return nil
	}
	group := make(map[string]json.RawMessage, len(r.request.GroupBy))
	var key strings.Builder
	for _, field := range r.request.GroupBy {
		value, ok := fields[field]
		if !ok {
			return fmt.Errorf("record missing aggregation field %q", field)
		}
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		group[field] = data
		fmt.Fprintf(&key, "%d:%s", len(data), data)
	}
	entry := r.groups[key.String()]
	if entry == nil {
		if len(r.groups) >= maxAggregateGroups {
			return errors.New("aggregation exceeds 4096 groups")
		}
		entry = &aggregateAccumulator{AggregateCount: AggregateCount{Group: group}}
		r.groups[key.String()] = entry
	}
	var value any
	if r.request.Field != "" {
		var ok bool
		value, ok = fields[r.request.Field]
		if !ok {
			return fmt.Errorf("record missing aggregation field %q", r.request.Field)
		}
	}
	return entry.add(r.request, value, r.retained)
}

func (r *aggregateReduction) result(source string, start, end time.Time) Snapshot {
	if len(r.metrics) != 0 {
		result := &AggregationResult{Start: start.UTC(), End: end.UTC(), GroupBy: append([]string{}, r.request.GroupBy...), Every: r.request.Every}
		for _, metric := range r.metrics {
			result.Metrics = append(result.Metrics, metric.result(source, start, end).Aggregation)
		}
		return Snapshot{Source: source, Time: end.UTC(), Aggregation: result}
	}
	keys := make([]string, 0, len(r.groups))
	for key := range r.groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	a := r.request
	result := &AggregationResult{Start: start.UTC(), End: end.UTC(), GroupBy: append([]string{}, a.GroupBy...), Function: a.Function, Field: a.Field, Percentile: a.Percentile, Every: a.Every}
	if a.Function == "" || a.Function == "count" {
		result.Counts = make([]AggregateCount, 0, len(keys))
	} else {
		result.Values = make([]AggregateValue, 0, len(keys))
	}
	for _, key := range keys {
		if a.Function == "" || a.Function == "count" {
			result.Counts = append(result.Counts, r.groups[key].AggregateCount)
		} else {
			result.Values = append(result.Values, AggregateValue{Group: r.groups[key].Group, Value: r.groups[key].value(a)})
		}
	}
	return Snapshot{Source: source, Time: end.UTC(), Aggregation: result}
}

func aggregateEvents(ctx context.Context, request MonitorRequest, source eventSource) (Snapshot, error) {
	if err := request.validate(); err != nil {
		return Snapshot{}, err
	}
	if request.Mode != "aggregate" {
		return Snapshot{}, errors.New("aggregate mode required")
	}
	start := time.Now()
	end := start.Add(request.Aggregation.Window)
	windowCtx, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	reduction := newAggregateReduction(*request.Aggregation)
	var collection *CollectionStats
	var mu sync.Mutex
	// Sources receive only the event selection, not the query mode.
	selection := request
	selection.Mode, selection.Aggregation = "", nil
	err := source(windowCtx, selection, func(event Event) error {
		mu.Lock()
		defer mu.Unlock()
		if event.Collection != nil {
			stats := *event.Collection
			collection = &stats
		}
		if event.Kind == "collection_stats" {
			return nil
		}
		if !time.Now().Before(end) || windowCtx.Err() != nil || !selection.matches(event) {
			return nil
		}
		return reduction.add(eventGroupFields(event, request.Stacks))
	})
	if ctx.Err() != nil {
		return Snapshot{}, ctx.Err()
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return Snapshot{}, err
	}
	if windowCtx.Err() != context.DeadlineExceeded {
		if err != nil {
			return Snapshot{}, err
		}
		return Snapshot{}, errors.New("event source stopped before aggregation window completed")
	}
	result := reduction.result(request.Source, start, end)
	result.Aggregation.Collection = collection
	return result, nil
}
