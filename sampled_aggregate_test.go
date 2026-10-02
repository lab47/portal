package portal

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestSampledQueryValidationAndProof(t *testing.T) {
	for _, query := range []string{
		"memory avg(used) over 30s", "memory count over 30s",
		"CPU AVG(utilization_percent) OVER 30s EVERY 500ms BY name",
		"network where name = eth* avg(bytes_recv_per_second) over 1m every 2s by name",
		"gpu percentile(temperature_celsius,95) over 5s every 100ms by uuid",
		"kernel max(counters.processes_running) over 10s every 1s",
		"containers count_distinct(id) over 10s every 1s",
		"process where name = worker* count over 10s every 1s by name",
		"process avg(cpu_percent) over 5s every 1s by pid,name",
		"process max(rss_bytes) over 5s every 1s by pid,name",
		"process avg(threads) over 5s every 1s by user,state",
	} {
		r, err := ParseMonitorQuery(query)
		if err != nil || !sampledAggregation(r) {
			t.Fatalf("sample query %q: %+v, %v", query, r, err)
		}
	}
	for _, query := range []string{
		"memory avg(used) over 1s every 0s", "memory avg(used) over 1s every -1s",
		"memory avg(used) over 1s every nope", "memory avg(used) over 1s every 99ms",
		"memory avg(used) over 1s every 2s", "memory avg(used) over 500ms",
		"cpu avg(user) over 30s", "network sum(bytes_sent) over 30s",
		"cpu avg(utilization_percent) over 1s every 1s", "process where action = start count over 1s every 100ms",
		"cpu count over 1s every 1s by utilization_percent",
		"process avg(cpu_seconds) over 5s every 1s", "process avg(cpu_percent) over 5s",
		"process avg(cpu_percent) over 1s every 1s", "process sum(pid) over 5s every 1s",
		"process count_distinct(action) over 1s every 100ms", "packets count over 1s every 100ms",
		"syscalls count over 1s every 100ms", "capabilities count over 1s every 100ms",
	} {
		if _, err := ParseMonitorQuery(query); err == nil {
			t.Fatalf("invalid sampled query accepted: %q", query)
		}
	}
	event, err := ParseMonitorQuery("process count over 1s by action")
	if err != nil || sampledAggregation(event) {
		t.Fatal("legacy process event aggregate changed")
	}
	r, err := ParseMonitorQuery("memory avg(used) over 3s every 500ms")
	if err != nil || r.Aggregation.Every != 500*time.Millisecond {
		t.Fatal("every not parsed")
	}
	ca, signer := testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	nonce := []byte(strings.Repeat("n", 32))
	proof, err := signMonitor(signer, cert, nonce, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err != nil {
		t.Fatal(err)
	}
	proof.Aggregation.Every = time.Second
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
		t.Fatal("sampling interval is not bound to the signature")
	}
}

func sampledFixture(t *testing.T, query string, snapshots []Snapshot) Snapshot {
	t.Helper()
	r, err := ParseMonitorQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	index := 0
	got, err := aggregateSnapshots(context.Background(), r, func(_ context.Context, selection MonitorRequest) (Snapshot, error) {
		if selection.Mode != "snapshot" || selection.Aggregation != nil {
			t.Fatal("sampler did not request snapshots")
		}
		if index >= len(snapshots) {
			t.Fatalf("unexpected sample %d", index)
		}
		snapshot := snapshots[index]
		snapshot.Source = r.Source
		index++
		return snapshot, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if index != len(snapshots) {
		t.Fatalf("collected %d snapshots, want %d", index, len(snapshots))
	}
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

func TestSampledGaugeFunctions(t *testing.T) {
	for _, tc := range []struct{ metric, want string }{
		{"count", "3"}, {"avg(temperature_celsius)", "4.500000000000000000"},
		{"sum(temperature_celsius)", "13.500000000000000000"}, {"min(temperature_celsius)", "1.250000000000000000"},
		{"max(temperature_celsius)", "9.500000000000000000"}, {"percentile(temperature_celsius,50)", "2.750000000000000000"},
		{"count_distinct(temperature_celsius)", "3"},
	} {
		synctest.Test(t, func(t *testing.T) {
			got := sampledFixture(t, "sensors "+tc.metric+" over 3s every 1s by name", []Snapshot{
				{Sensors: []SensorInfo{{Name: "chip", Temperature: 1.25}}},
				{Sensors: []SensorInfo{{Name: "chip", Temperature: 9.5}}},
				{Sensors: []SensorInfo{{Name: "chip", Temperature: 2.75}}},
			})
			if tc.metric == "count" {
				if len(got.Aggregation.Counts) != 1 || got.Aggregation.Counts[0].Count != 3 {
					t.Fatal("wrong sampled record count")
				}
			} else if len(got.Aggregation.Values) != 1 || string(got.Aggregation.Values[0].Value) != tc.want {
				t.Fatalf("%s: %+v, want %s", tc.metric, got.Aggregation.Values, tc.want)
			}
			if got.Aggregation.Every != time.Second || got.Aggregation.End.Sub(got.Aggregation.Start) != 3*time.Second {
				t.Fatal("incorrect sampled window")
			}
		})
	}
	synctest.Test(t, func(t *testing.T) {
		got := sampledFixture(t, "memory avg(used) over 2s", []Snapshot{{Memory: &MemoryInfo{Used: ^uint64(0) - 2}}, {Memory: &MemoryInfo{Used: ^uint64(0)}}})
		if string(got.Aggregation.Values[0].Value) != "18446744073709551614.000000000000000000" {
			t.Fatal("lost full-width integer precision")
		}
	})
}

func TestSampledCPUUtilization(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		got := sampledFixture(t, "cpu avg(utilization_percent) over 3s every 1s by name", []Snapshot{
			{CPU: []CPUInfo{{Name: "cpu0", Total: 1000, Idle: 800, IOWait: 50}, {Name: "cpu1", Total: 2000, Idle: 1500, IOWait: 100}}},
			{CPU: []CPUInfo{{Name: "cpu1", Total: 2010, Idle: 1507, IOWait: 102}, {Name: "cpu0", Total: 1010, Idle: 804, IOWait: 51}}},
			{CPU: []CPUInfo{{Name: "cpu0", Total: 1030, Idle: 808, IOWait: 52}, {Name: "cpu1", Total: 2030, Idle: 1517, IOWait: 104}}},
		})
		values := got.Aggregation.Values
		if len(values) != 2 || string(values[0].Group["name"]) != `"cpu0"` || string(values[0].Value) != "62.500000000000000000" || string(values[1].Value) != "25.000000000000000000" {
			t.Fatalf("incorrect utilization or CPU identity: %+v", values)
		}
	})
}

func TestSampledProcessMetrics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cpu := []float64{10, 100, 11.5, 100.25, 50, 100.75, 52, 101.5}
		rss := []uint64{100, 1000, 300, 500, 200, 2000, 400, 1000}
		var snapshots []Snapshot
		for i := 0; i < 4; i++ {
			started := time.Unix(1, 0)
			if i >= 2 {
				started = time.Unix(2, 0) // Reused PID with a larger counter must still start a new baseline.
			}
			snapshots = append(snapshots, Snapshot{Processes: []ProcessInfo{
				{PID: 71, Name: "worker", Started: started, CPUSeconds: &cpu[2*i], RSSBytes: &rss[2*i]},
				{PID: 72, Name: "worker", Started: time.Unix(1, 0), CPUSeconds: &cpu[2*i+1], RSSBytes: &rss[2*i+1]},
			}})
		}
		for _, tc := range []struct{ metric, first, second string }{
			{"avg(cpu_percent)", "175.000000000000000000", "50.000000000000000000"},
			{"avg(rss_bytes)", "250.000000000000000000", "1125.000000000000000000"},
		} {
			got := sampledFixture(t, "process "+tc.metric+" over 4s every 1s by pid,name", snapshots)
			values := got.Aggregation.Values
			if len(values) != 2 || string(values[0].Group["pid"]) != "71" || string(values[0].Value) != tc.first || string(values[1].Value) != tc.second {
				t.Fatalf("%s lost scale, PID identity, or precision: %+v", tc.metric, values)
			}
		}
		missing := sampledFixture(t, "process avg(cpu_percent) over 3s every 1s", []Snapshot{
			{Processes: []ProcessInfo{{PID: 71, Started: time.Unix(1, 0), CPUSeconds: &cpu[0]}}},
			{Processes: []ProcessInfo{{PID: 71, Started: time.Unix(1, 0)}}},
			{Processes: []ProcessInfo{{PID: 71, Started: time.Unix(1, 0), CPUSeconds: &cpu[2]}}},
		})
		if string(missing.Aggregation.Values[0].Value) != "null" {
			t.Fatal("missing CPU counter must restart the baseline, not fabricate a measurement")
		}
	})
	at := time.Now()
	fields := map[string]any{"cpu_seconds": json.Number("13")}
	deriveSample(fields, sampleObservation{map[string]any{"cpu_seconds": json.Number("10")}, at}, at.Add(2*time.Second), snapshotSampleFields("process"))
	if fields["cpu_percent"] != json.Number("150.000000000000000000") {
		t.Fatal("process CPU did not use actual elapsed time or was clamped to 100%")
	}
}

func TestCounterRatesAndLifecycles(t *testing.T) {
	at := time.Now()
	metadata := snapshotSampleFields("network")
	previous := sampleObservation{map[string]any{"bytes_recv": json.Number("18446744073709551500")}, at}
	current := map[string]any{"bytes_recv": json.Number("18446744073709551510")}
	deriveSample(current, previous, at.Add(2*time.Second), metadata)
	if current["bytes_recv_per_second"] != json.Number("5.000000000000000000") {
		t.Fatal("rate used nominal interval or lost counter precision")
	}
	reset := map[string]any{"bytes_recv": json.Number("2")}
	deriveSample(reset, previous, at.Add(time.Second), metadata)
	if reset["bytes_recv_per_second"] != nil {
		t.Fatal("counter reset became a negative/huge rate")
	}
	synctest.Test(t, func(t *testing.T) {
		got := sampledFixture(t, "network avg(bytes_recv_per_second) over 6s every 1s by name", []Snapshot{
			{Network: []InterfaceInfo{{Name: "eth0", Index: 7, BytesRecv: 100}}},
			{Network: []InterfaceInfo{{Name: "eth0", Index: 7, BytesRecv: 110}}},
			{Network: nil}, // Disappearance must discard the old baseline.
			{Network: []InterfaceInfo{{Name: "eth0", Index: 7, BytesRecv: 1000}}},
			{Network: []InterfaceInfo{{Name: "eth0", Index: 7, BytesRecv: 2}}}, // Reset is a new baseline.
			{Network: []InterfaceInfo{{Name: "eth0", Index: 7, BytesRecv: 22}}},
		})
		if len(got.Aggregation.Values) != 1 || string(got.Aggregation.Values[0].Value) != "15.000000000000000000" {
			t.Fatalf("bad reset/missing semantics: %+v", got.Aggregation.Values)
		}
	})
}

func TestSampledMissingFailuresAndSlowReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		value := 40.0
		got := sampledFixture(t, "gpu avg(utilization_percent) over 3s every 1s by uuid", []Snapshot{{GPUs: []GPUInfo{{UUID: "gpu-a"}}}, {GPUs: []GPUInfo{{UUID: "gpu-a", Utilization: &value}}}, {GPUs: []GPUInfo{{UUID: "gpu-a"}}}})
		if string(got.Aggregation.Values[0].Value) != "40.000000000000000000" {
			t.Fatal("missing GPU metric counted as zero")
		}
		empty := sampledFixture(t, "cpu avg(utilization_percent) over 2s by name", []Snapshot{{}, {}})
		if empty.Aggregation.Values == nil || len(empty.Aggregation.Values) != 0 {
			t.Fatal("empty grouped sample result must be []")
		}
		null := sampledFixture(t, "gpu avg(power_watts) over 1s", []Snapshot{{GPUs: []GPUInfo{{UUID: "gpu-a"}}}})
		if string(null.Aggregation.Values[0].Value) != "null" {
			t.Fatal("missing ungrouped metric must be null")
		}
		r, _ := ParseMonitorQuery("memory avg(used) over 5s every 1s")
		failure := errors.New("collector failed")
		if _, err := aggregateSnapshots(context.Background(), r, func(context.Context, MonitorRequest) (Snapshot, error) { return Snapshot{}, failure }); !errors.Is(err, failure) {
			t.Fatal("collector failure hidden")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if _, err := aggregateSnapshots(ctx, r, func(context.Context, MonitorRequest) (Snapshot, error) {
			return Snapshot{Source: "memory", Memory: &MemoryInfo{Used: 7}}, nil
		}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("cancellation returned a partial success: %v", err)
		}
		start := time.Now()
		var calls []time.Duration
		got, err := aggregateSnapshots(context.Background(), r, func(ctx context.Context, _ MonitorRequest) (Snapshot, error) {
			calls = append(calls, time.Since(start))
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-ctx.Done():
				return Snapshot{}, ctx.Err()
			}
			return Snapshot{Source: "memory", Memory: &MemoryInfo{Used: 7}}, nil
		})
		if err != nil || !reflect.DeepEqual(calls, []time.Duration{0, 2 * time.Second, 4 * time.Second}) || string(got.Aggregation.Values[0].Value) != "7.000000000000000000" {
			t.Fatalf("slow collection caused catch-up: %v, %v", calls, err)
		}
	})
}
