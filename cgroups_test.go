package portal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestCgroupQueriesAndProof(t *testing.T) {
	for _, text := range []string{"cgroups", "cgroups where path = /system.slice/*", "cgroups where path = *.service avg(cpu_percent) over 5s by path", "cgroups max(memory_bytes) over 3s every 100ms by path,id"} {
		if _, err := ParseMonitorQuery(text); err != nil {
			t.Fatalf("valid cgroup query %q: %v", text, err)
		}
	}
	for _, text := range []string{"cgroups where name = web", "cgroups where path = /foo*bar", "cgroups where pid = 1", "cgroups sum(cpu_seconds) over 3s", "cgroups avg(cpu_percent) over 1s every 1s", "cgroups where path = '*'"} {
		if _, err := ParseMonitorQuery(text); err == nil {
			t.Fatalf("invalid cgroup query accepted: %s", text)
		}
	}
	if err := (MonitorRequest{Source: "cgroups"}).validate(); err == nil {
		t.Fatal("cgroups must not be an event monitor")
	}
	if err := (MonitorRequest{Source: "memory", Mode: "snapshot", Path: "/"}).validate(); err == nil {
		t.Fatal("cgroup filter accepted on unrelated source")
	}
	r, _ := ParseMonitorQuery("cgroups where path = /system.slice/*")
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
	proof.Path = "/"
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
		t.Fatal("cgroup path filter not signed")
	}
	p := policy{"operator": {fmt.Sprint(os.Geteuid()): true}}
	err = authorizeMonitorSource(p, cert, "cgroups")
	if (os.Geteuid() == 0) != (err == nil) {
		t.Fatalf("cgroup root authorization: %v", err)
	}
	if err := authorizeMonitorSource(policy{"operator": {"other-uid": true}}, cert, "cgroups"); err == nil {
		t.Fatal("cgroups exposed without root policy")
	}
	encoded, err := json.Marshal(Snapshot{Source: "cgroups"})
	if err != nil || !strings.Contains(string(encoded), `"cgroups":[]`) {
		t.Fatalf("empty cgroup collection: %s, %v", encoded, err)
	}
	if runtime.GOOS != "linux" {
		if _, err := readCgroups(context.Background(), ""); err == nil {
			t.Fatal("non-Linux cgroup source succeeded")
		}
	}
}

func TestCgroupSampledMetrics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cpu := []float64{10, 13, 100, 101}
		memory := []uint64{^uint64(0) - 6, ^uint64(0) - 4, ^uint64(0) - 2, ^uint64(0)}
		var snapshots []Snapshot
		for i := range cpu {
			id := "1:7"
			if i >= 2 {
				id = "1:9" // Same path, recreated directory; counter increased, not reset.
			}
			snapshots = append(snapshots, Snapshot{Cgroups: []CgroupInfo{{Path: "/web", ID: id, CPUSeconds: &cpu[i], MemoryBytes: &memory[i]}}})
		}
		for _, tc := range []struct{ metric, want string }{
			{"avg(cpu_percent)", "200.000000000000000000"},
			{"avg(memory_bytes)", "18446744073709551612.000000000000000000"},
		} {
			got := sampledFixture(t, "cgroups "+tc.metric+" over 4s every 1s by path", snapshots)
			if len(got.Aggregation.Values) != 1 || string(got.Aggregation.Values[0].Value) != tc.want || string(got.Aggregation.Values[0].Group["path"]) != `"/web"` {
				t.Fatalf("cgroup %s: %+v", tc.metric, got.Aggregation.Values)
			}
		}
	})
}
