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

func TestProbeQueries(t *testing.T) {
	text := `syscalls:completion where syscall in (:fsync, :fdatasync) {
  let caller = stack.user(from: ["os.(*File).Sync", glob("*Fdatasync")], offsets: false)
  let directory = path.prefix(file.path, 3)
  @syncs[process_name, directory, caller] = {calls: count(), elapsed: sum(duration_ns), p95: percentile(duration_ns, 95)}
} after 30s { emit @syncs order by elapsed desc limit 25 }`
	r, err := ParseMonitorQuery(text)
	if err != nil {
		t.Fatal(err)
	}
	if r.Phase != "completion" || !r.Paths || r.FileDepth != 3 || r.Stacks == nil || !r.Stacks.User || !r.Stacks.UserShape.DropOffsets || r.Aggregation.SortMetric != 1 || r.Aggregation.Limit != 25 || r.Aggregation.Table != "syncs" || r.Aggregation.Metrics[2].Name != "p95" || r.Aggregation.GroupAliases["user.stack"] != "caller" {
		t.Fatalf("incorrect lowering: %+v", r)
	}
	for _, query := range []string{
		`disk:completion where operation == write { @writes[device_name, io.cgroup.path] = {requests: count(), sectors: sum(sectors)} } every 30s { emit @writes; clear @writes } after 5m { stop }`,
		`packets where protocol = tcp and dst.port = 80 { @traffic[src.ip] = sum(length) } after 30s { emit @traffic }`,
		`process:start { @starts[name] = count() } after 1s { emit @starts }`,
		`memory { @usage[] = avg(used) } after 2s { emit @usage }`,
		`tracepoint:sched:sched_switch where fields in (prev_pid) { @switches[field.prev_pid] = count() } after 1s { emit @switches }`,
	} {
		if _, err := ParseMonitorQuery(query); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	for _, query := range []string{
		`disk { @x[] = count() } after 0s { emit @x }`,
		`disk { @x[] = count() } every 30s { emit @x } after 5m { stop }`,
		`disk { @x[] = count() } every 30s { emit @x; clear @wrong } after 5m { stop }`,
		`disk { @x[] = count() } every 1ms { emit @x; clear @x } after 5m { stop }`,
		`disk { @x[] = count() } after 1s { emit @wrong }`,
		`disk { @x[] = count() } after 1s { emit @x order by missing desc }`,
		`disk { @x[] = {a: count(), a: sum(sectors)} } after 1s { emit @x }`,
		`disk { @x[] = {a: count(), b: count()} } after 1s { emit @x }`,
		`disk { @x[] = system("rm") } after 1s { emit @x }`,
		`disk { @x[] = count(); @y[] = count() } after 1s { emit @x }`,
		`syscalls where syscall in () { @x[] = count() } after 1s { emit @x }`,
		`syscalls { let x = stack.user(from: []); @x[x] = count() } after 1s { emit @x }`,
		`syscalls { let x = path.prefix("file.path", 3); @x[x] = count() } after 1s { emit @x }`,
		"process where name = \"raw\nnewline\" { @x[] = count() } after 1s { emit @x }",
	} {
		if _, err := ParseMonitorQuery(query); err == nil {
			t.Fatalf("accepted %s", query)
		}
	}
}

func TestProbeBuckets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, err := ParseMonitorQuery(`syscalls:completion { let process = pid; @cost[process] = {calls: count(), cost: sum(duration_ns)} } every 1s { emit @cost; clear @cost } after 2500ms { stop }`)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		result, err := aggregateEvents(context.Background(), r, func(ctx context.Context, selection MonitorRequest, emit func(Event) error) error {
			calls++
			if selection.Mode != "" || selection.Aggregation != nil {
				t.Fatal("query controls reached collector")
			}
			for _, sample := range []struct {
				wait  time.Duration
				pid   uint32
				value uint64
			}{{999 * time.Millisecond, 7, 3}, {time.Millisecond, 7, 11}, {1200 * time.Millisecond, 9, 17}} {
				time.Sleep(sample.wait)
				value := sample.value
				if err := emit(Event{PID: sample.pid, DurationNS: &value}); err != nil {
					return err
				}
			}
			<-ctx.Done()
			// A boundary event must not leak into the shortened last bucket.
			value := uint64(100)
			if err := emit(Event{PID: 9, DurationNS: &value}); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if calls != 1 || len(result.Windows) != 3 || result.Aggregation != nil {
			t.Fatalf("subscriptions=%d result=%+v", calls, result)
		}
		for i, want := range []string{"3", "11", "17"} {
			a := result.Windows[i]
			if a.Table != "cost" || len(a.Rows) != 1 || string(a.Rows[0].Values[0]) != "1" || string(a.Rows[0].Values[1]) != want || a.Columns[1].Name != "cost" || !reflect.DeepEqual(a.GroupBy, []string{"process"}) {
				t.Fatalf("bucket %d: %+v", i, a)
			}
			if i > 0 && !a.Start.Equal(result.Windows[i-1].End) {
				t.Fatal("bucket gap")
			}
		}
		if result.Windows[2].End.Sub(result.Windows[2].Start) != 500*time.Millisecond {
			t.Fatal("partial final bucket not retained")
		}
		encoded, err := json.Marshal(result)
		if err != nil || !strings.Contains(string(encoded), `"windows"`) || !strings.Contains(string(encoded), `"process":7`) {
			t.Fatalf("wire format: %s %v", encoded, err)
		}
	})
}

func TestProbeSourceFailure(t *testing.T) {
	r, err := ParseMonitorQuery(`disk { @x[] = count() } every 1s { emit @x; clear @x } after 2s { stop }`)
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("failed capture")
	if _, err := aggregateEvents(context.Background(), r, func(context.Context, MonitorRequest, func(Event) error) error { return want }); !errors.Is(err, want) {
		t.Fatalf("source failure hidden: %v", err)
	}
}

func TestProbeProofAndCompatibility(t *testing.T) {
	r, err := ParseMonitorQuery(`syscalls { let process = pid; @x[process] = {calls: count(), total: sum(syscall)} } every 1s { emit @x; clear @x } after 3s { stop }`)
	if err != nil {
		t.Fatal(err)
	}
	ca, signer := testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	for _, mutate := range []func(*MonitorRequest){
		func(r *MonitorRequest) { r.Aggregation.ReportEvery = 2 * time.Second },
		func(r *MonitorRequest) { r.Aggregation.GroupAliases["pid"] = "other" },
		func(r *MonitorRequest) { r.Aggregation.Metrics[0].Name = "other" },
		func(r *MonitorRequest) { r.Aggregation.Table = "other" },
	} {
		data, _ := json.Marshal(r)
		var fresh MonitorRequest
		if err := json.Unmarshal(data, &fresh); err != nil {
			t.Fatal(err)
		}
		proof, err := signMonitor(signer, cert, []byte("nonce"), fresh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyMonitor(ca.PublicKey(), "admin", []byte("nonce"), proof); err != nil {
			t.Fatal(err)
		}
		mutate(&proof.MonitorRequest)
		if _, err := verifyMonitor(ca.PublicKey(), "admin", []byte("nonce"), proof); err == nil {
			t.Fatal("unsigned probe control")
		}
	}
	if legacy, err := ParseMonitorQuery(`process where name = "worker{test}" count over 1s`); err != nil || legacy.Process.Name != "worker{test}" || legacy.Aggregation.Compact || legacy.Aggregation.Table != "" {
		t.Fatalf("legacy syntax changed: %+v, %v", legacy, err)
	}
}

func TestProbeSeriesGroupBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, err := ParseMonitorQuery(`syscalls { @x[pid] = count() } every 1s { emit @x; clear @x } after 2s { stop }`)
		if err != nil {
			t.Fatal(err)
		}
		_, err = aggregateEvents(context.Background(), r, func(ctx context.Context, _ MonitorRequest, emit func(Event) error) error {
			for bucket := 0; bucket < 2; bucket++ {
				if bucket == 1 {
					time.Sleep(time.Second)
				}
				for i := 1; i <= 2049; i++ {
					if err := emit(Event{PID: uint32(i)}); err != nil {
						return err
					}
				}
			}
			<-ctx.Done()
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "4096 retained") {
			t.Fatalf("series bypassed group budget: %v", err)
		}
	})
}

func FuzzProbeQueries(f *testing.F) {
	for _, seed := range []string{`disk { @x[] = count() } after 1s { emit @x }`, `disk where operation = [write,read] { @x[] = count() } after 1s { emit @x }`, `syscalls { let x = stack.user(from: []); @x[x] = count() } after 1s { emit @x }`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		r, err := ParseMonitorQuery(text)
		if err == nil && r.Source != "capabilities" {
			if err := r.validate(); err != nil {
				t.Fatalf("parser accepted invalid request: %v", err)
			}
		}
	})
}
