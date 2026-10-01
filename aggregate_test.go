package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestAggregateWindowAndFilters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		request, err := ParseMonitorQuery("syscalls where syscall = 2 count over 30s by pid")
		if err != nil {
			t.Fatal(err)
		}
		source := func(ctx context.Context, r MonitorRequest, emit func(Event) error) error {
			if r.Mode != "" || r.Aggregation != nil {
				t.Fatal("query spec leaked into event source")
			}
			for _, e := range []Event{{PID: 7, Syscall: 2}, {PID: 42, Syscall: 2}, {PID: 99, Syscall: 3}} {
				if err := emit(e); err != nil {
					return err
				}
			}
			time.Sleep(30*time.Second - time.Nanosecond)
			if err := emit(Event{PID: 7, Syscall: 2, Time: time.Now().Add(-time.Hour)}); err != nil {
				return err
			}
			time.Sleep(time.Nanosecond)
			if err := emit(Event{PID: 42, Syscall: 2}); err != nil {
				return err
			}
			<-ctx.Done()
			return nil
		}
		start := time.Now()
		got, err := aggregateEvents(context.Background(), request, source)
		if err != nil {
			t.Fatal(err)
		}
		want := []AggregateCount{{Group: map[string]json.RawMessage{"pid": json.RawMessage(`7`)}, Count: 2}, {Group: map[string]json.RawMessage{"pid": json.RawMessage(`42`)}, Count: 1}}
		if !reflect.DeepEqual(got.Aggregation.Counts, want) || !got.Aggregation.Start.Equal(start) || !got.Aggregation.End.Equal(start.Add(30*time.Second)) || !got.Time.Equal(got.Aggregation.End) {
			t.Fatalf("wrong window or counts: %+v", got.Aggregation)
		}
	})
}

func TestAggregateOtherSources(t *testing.T) {
	for _, tc := range []struct {
		query string
		event Event
		group string
	}{
		{"process count over 1s by name,action", Event{Process: &ProcessEvent{Name: "worker", Action: "start"}}, `{"action":"start","name":"worker"}`},
		{"packets count over 1s by dst.port,src.ip", Event{Packet: &PacketEvent{DestinationPort: 80, SourceIP: "192.0.2.7"}}, `{"dst.port":80,"src.ip":"192.0.2.7"}`},
		{"disk count over 1s by device,operation", Event{Disk: &DiskEvent{Device: 12, Operation: "read"}}, `{"device":12,"operation":"read"}`},
		{"tracepoint where event = custom:sample and fields in (value) count over 1s by field.value", Event{Tracepoint: &TracepointEvent{Event: "custom:sample", Fields: map[string]json.Number{"value": "18446744073709551615"}}}, `{"field.value":18446744073709551615}`},
	} {
		t.Run(tc.query, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				request, err := ParseMonitorQuery(tc.query)
				if err != nil {
					t.Fatal(err)
				}
				got, err := aggregateEvents(context.Background(), request, func(ctx context.Context, _ MonitorRequest, emit func(Event) error) error {
					if err := emit(tc.event); err != nil {
						return err
					}
					<-ctx.Done()
					return ctx.Err()
				})
				if err != nil || len(got.Aggregation.Counts) != 1 || got.Aggregation.Counts[0].Count != 1 {
					t.Fatalf("count: %+v, %v", got, err)
				}
				group, _ := json.Marshal(got.Aggregation.Counts[0].Group)
				if string(group) != tc.group {
					t.Fatalf("group = %s, want %s", group, tc.group)
				}
				data, _ := json.Marshal(got)
				if strings.Contains(string(data), `"processes"`) {
					t.Fatal("aggregation mislabeled as a process snapshot")
				}
			})
		})
	}
}

func TestAggregateEmptyAndFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, group := range [][]string{nil, {"pid"}} {
			r := MonitorRequest{Source: "syscalls", Mode: "aggregate", Aggregation: &AggregationRequest{Window: time.Second, GroupBy: group}}
			got, err := aggregateEvents(context.Background(), r, func(ctx context.Context, _ MonitorRequest, _ func(Event) error) error { <-ctx.Done(); return nil })
			if err != nil || got.Aggregation.Counts == nil {
				t.Fatalf("empty window: %+v, %v", got, err)
			}
			if len(group) == 0 && (len(got.Aggregation.Counts) != 1 || got.Aggregation.Counts[0].Count != 0) || len(group) != 0 && len(got.Aggregation.Counts) != 0 {
				t.Fatalf("empty count semantics: %+v", got.Aggregation)
			}
		}
		r := MonitorRequest{Source: "syscalls", Mode: "aggregate", Aggregation: &AggregationRequest{Window: time.Second}}
		failure := errors.New("source failed")
		if _, err := aggregateEvents(context.Background(), r, func(context.Context, MonitorRequest, func(Event) error) error { return failure }); !errors.Is(err, failure) {
			t.Fatalf("source failure hidden: %v", err)
		}
		if _, err := aggregateEvents(context.Background(), r, func(context.Context, MonitorRequest, func(Event) error) error { return nil }); err == nil {
			t.Fatal("partial window reported as complete")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if _, err := aggregateEvents(ctx, r, func(ctx context.Context, _ MonitorRequest, _ func(Event) error) error { <-ctx.Done(); return nil }); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("caller cancellation became a result: %v", err)
		}
	})
}

func TestAggregateGroupLimit(t *testing.T) {
	for _, size := range []int{4096, 4097} {
		synctest.Test(t, func(t *testing.T) {
			r := MonitorRequest{Source: "syscalls", Mode: "aggregate", Aggregation: &AggregationRequest{Window: time.Second, GroupBy: []string{"pid"}}}
			got, err := aggregateEvents(context.Background(), r, func(ctx context.Context, _ MonitorRequest, emit func(Event) error) error {
				for i := 1; i <= size; i++ {
					if err := emit(Event{PID: uint32(i)}); err != nil {
						return err
					}
				}
				<-ctx.Done()
				return nil
			})
			if size == 4096 && (err != nil || len(got.Aggregation.Counts) != 4096) || size == 4097 && (err == nil || !strings.Contains(err.Error(), "4096 groups")) {
				t.Fatalf("group limit %d: %+v, %v", size, got, err)
			}
		})
	}
}

func TestAggregateCompoundGroups(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, err := ParseMonitorQuery("process count over 1s by name,action")
		if err != nil {
			t.Fatal(err)
		}
		got, err := aggregateEvents(context.Background(), r, func(ctx context.Context, _ MonitorRequest, emit func(Event) error) error {
			for _, process := range []ProcessEvent{{Name: "worker", Action: "start"}, {Name: "worker", Action: "exit"}, {Name: "worker", Action: "start"}, {Name: "other", Action: "start"}} {
				if err := emit(Event{Process: &process}); err != nil {
					return err
				}
			}
			<-ctx.Done()
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		counts := make(map[string]uint64)
		for _, count := range got.Aggregation.Counts {
			group, err := json.Marshal(count.Group)
			if err != nil {
				t.Fatal(err)
			}
			counts[string(group)] = count.Count
		}
		want := map[string]uint64{`{"action":"start","name":"worker"}`: 2, `{"action":"exit","name":"worker"}`: 1, `{"action":"start","name":"other"}`: 1}
		if !reflect.DeepEqual(counts, want) {
			t.Fatalf("compound grouping ignored a field: %v", counts)
		}
	})
}

func aggregateFixture(t *testing.T, query string, events []Event) Snapshot {
	t.Helper()
	r, err := ParseMonitorQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	got, err := aggregateEvents(context.Background(), r, func(ctx context.Context, _ MonitorRequest, emit func(Event) error) error {
		for _, event := range events {
			if err := emit(event); err != nil {
				return err
			}
		}
		<-ctx.Done()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Verify the wire representation, including full-width integers.
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Snapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestAggregateFunctions(t *testing.T) {
	for _, tc := range []struct{ metric, first, second string }{
		{"sum(field.value)", "17", "12"},
		{"avg(field.value)", "3.400000000000000000", "6.000000000000000000"},
		{"min(field.value)", "-5", "3"},
		{"max(field.value)", "18", "9"},
		{"count_distinct(field.value)", "4", "2"},
		{"percentile(field.value, 50)", "2", "3"},
		{"percentile(field.value, 0)", "-5", "3"},
		{"percentile(field.value, 100)", "18", "9"},
		{"percentile(field.value, 99.9)", "18", "9"},
	} {
		t.Run(tc.metric, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var events []Event
				for i, values := range [][]string{{"-5", "0", "2", "18", "2"}, {"9", "3"}} {
					for _, value := range values {
						events = append(events, Event{Tracepoint: &TracepointEvent{Event: "custom:sample", Fields: map[string]json.Number{"value": json.Number(value), "group": json.Number(fmt.Sprint(i + 1))}}})
					}
				}
				got := aggregateFixture(t, "tracepoint where event = custom:sample and fields in (value,group) "+tc.metric+" over 1s by field.group", events)
				values := got.Aggregation.Values
				if len(values) != 2 || string(values[0].Group["field.group"]) != "1" || string(values[1].Group["field.group"]) != "2" || string(values[0].Value) != tc.first || string(values[1].Value) != tc.second || got.Aggregation.Counts != nil {
					t.Fatalf("grouped values: %+v; want %s, %s", values, tc.first, tc.second)
				}
			})
		})
	}
}

func TestAggregatePrecision(t *testing.T) {
	for _, tc := range []struct {
		metric, want string
		input        []string
	}{
		{"sum(field.x)", "36893488147419103230", []string{"18446744073709551615", "18446744073709551615"}},
		{"avg(field.x)", "18446744073709551614.500000000000000000", []string{"18446744073709551615", "18446744073709551614"}},
		{"min(field.x)", "9007199254740992", []string{"9007199254740993", "9007199254740992"}},
		{"max(field.x)", "9007199254740993", []string{"9007199254740992", "9007199254740993"}},
		{"avg(field.x)", "0.333333333333333333", []string{"0", "0", "1"}},
		{"percentile(field.x, 50)", "9007199254740992", []string{"9007199254740993", "9007199254740992"}},
	} {
		t.Run(tc.metric+tc.want, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var events []Event
				for _, value := range tc.input {
					events = append(events, Event{Tracepoint: &TracepointEvent{Event: "custom:sample", Fields: map[string]json.Number{"x": json.Number(value)}}})
				}
				got := aggregateFixture(t, "tracepoint where event = custom:sample and fields in (x) "+tc.metric+" over 1s", events)
				if len(got.Aggregation.Values) != 1 || string(got.Aggregation.Values[0].Value) != tc.want {
					t.Fatalf("precision lost: %+v, want %s", got.Aggregation.Values, tc.want)
				}
			})
		})
	}
}

func TestAggregateNumericAndEmptyFields(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, tc := range []struct {
			query, want string
			events      []Event
		}{
			{"packets where protocol = tcp sum(length) over 1s", "134", []Event{{Packet: &PacketEvent{Protocol: "tcp", Length: 120}}, {Packet: &PacketEvent{Protocol: "udp", Length: 1000}}, {Packet: &PacketEvent{Protocol: "tcp", Length: 14}}}},
			{"disk sum(sectors) over 1s", "19", []Event{{Disk: &DiskEvent{Sectors: 8}}, {Disk: &DiskEvent{Sectors: 11}}}},
			{"process count_distinct(name) over 1s", "2", []Event{{Process: &ProcessEvent{Name: "worker"}}, {Process: &ProcessEvent{Name: "other"}}, {Process: &ProcessEvent{Name: "worker"}}}},
			{"packets sum(length) over 1s", "0", nil},
			{"process count_distinct(name) over 1s", "0", nil},
			{"packets avg(length) over 1s", "null", nil},
			{"packets min(length) over 1s", "null", nil},
			{"packets max(length) over 1s", "null", nil},
			{"packets percentile(length,95) over 1s", "null", nil},
		} {
			got := aggregateFixture(t, tc.query, tc.events)
			if len(got.Aggregation.Values) != 1 || string(got.Aggregation.Values[0].Value) != tc.want {
				t.Fatalf("%s: %+v, want %s", tc.query, got.Aggregation.Values, tc.want)
			}
		}
		got := aggregateFixture(t, "packets sum(length) over 1s by dst.port", nil)
		if got.Aggregation.Values == nil || len(got.Aggregation.Values) != 0 {
			t.Fatalf("empty grouped values must be []: %+v", got.Aggregation)
		}
	})
	for _, p := range []float64{-1, 101, math.NaN(), math.Inf(1)} {
		r := MonitorRequest{Source: "syscalls", Mode: "aggregate", Aggregation: &AggregationRequest{Window: time.Second, Function: "percentile", Field: "pid", Percentile: p}}
		if err := r.validate(); err == nil {
			t.Fatalf("invalid percentile accepted: %v", p)
		}
	}
}

func TestAggregateRetainedValueLimit(t *testing.T) {
	for _, function := range []string{"count_distinct", "percentile"} {
		t.Run(function, func(t *testing.T) {
			a := AggregationRequest{Function: function, Field: "pid"}
			if function == "percentile" {
				a.Percentile = 95
			}
			var groups [2]aggregateAccumulator
			retained := 0
			for i := 0; i < 65536; i++ {
				if err := groups[i%2].add(a, i/2, &retained); err != nil {
					t.Fatalf("failed below shared limit: %v", err)
				}
			}
			if function == "count_distinct" {
				if err := groups[0].add(a, 0, &retained); err != nil || retained != 65536 {
					t.Fatalf("duplicate consumed distinct capacity: %d, %v", retained, err)
				}
			}
			if err := groups[0].add(a, 32768, &retained); err == nil || !strings.Contains(err.Error(), "65536 retained values") {
				t.Fatalf("query-wide capacity not enforced: %v", err)
			}
		})
	}
}

func TestAggregatePercentileRanks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var events []Event
		for i := 100; i >= 1; i-- {
			events = append(events, Event{PID: uint32(i)})
		}
		for _, tc := range []struct{ percent, want string }{{"0", "1"}, {"7", "7"}, {"7.01", "8"}, {"50", "50"}, {"100", "100"}} {
			got := aggregateFixture(t, "syscalls percentile(pid,"+tc.percent+") over 1s", events)
			if string(got.Aggregation.Values[0].Value) != tc.want {
				t.Fatalf("percentile %s: %s, want %s", tc.percent, got.Aggregation.Values[0].Value, tc.want)
			}
		}
	})
}
