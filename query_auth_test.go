package portal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAggregateJoinSigning(t *testing.T) {
	const selectors = `syscalls { @a[proc: pid] = {ops: count(), total: sum(pid)} }
disk { @b[proc: pid] = {ops: count(), sectors: sum(sectors)} } `
	r, err := ParseMonitorQuery(selectors + `after 1s { emit @a left join @b on proc order by sectors desc limit 2 }`)
	if err != nil {
		t.Fatal(err)
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
	proof.Reports[0].Kind = "full"
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
		t.Fatal("join semantics not bound to signed query")
	}
}

func TestAggregateReportSigning(t *testing.T) {
	r, err := ParseMonitorQuery(`syscalls { @a[who: pid, call: syscall] = {ops: count(), total: sum(pid)} } after 1s { emit @a rollup by who select x = ops / 2 }`)
	if err != nil {
		t.Fatal(err)
	}
	ca, signer := testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	nonce := []byte(strings.Repeat("n", 32))
	for _, mutate := range []func(*monitorRequest){
		func(r *monitorRequest) { r.Reports[0].LeftRollup[0] = "call" },
		func(r *monitorRequest) { r.Reports[0].Select[0].Expression.Args[1].Value = "3" },
	} {
		data, _ := json.Marshal(r)
		var copy MonitorRequest
		if err := json.Unmarshal(data, &copy); err != nil {
			t.Fatal(err)
		}
		proof, err := signMonitor(signer, cert, nonce, copy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err != nil {
			t.Fatal(err)
		}
		mutate(&proof)
		if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
			t.Fatal("report projection not bound to signed request")
		}
	}
}

func TestCgroupQuerySigningAndAuthorization(t *testing.T) {
	r, err := ParseMonitorQuery("cgroups where path = /system.slice/*")
	if err != nil {
		t.Fatal(err)
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
	proof.Path = "/"
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
		t.Fatal("cgroup path filter not signed")
	}
	p := policy{"operator": {fmt.Sprint(os.Geteuid()): true}}
	err = authorizeMonitorSource(p, cert.KeyId, "cgroups")
	if (os.Geteuid() == 0) != (err == nil) {
		t.Fatalf("cgroup root authorization: %v", err)
	}
	if err := authorizeMonitorSource(policy{"operator": {"other-uid": true}}, cert.KeyId, "cgroups"); err == nil {
		t.Fatal("cgroups exposed without root policy")
	}
}

func TestEventFilterSigning(t *testing.T) {
	r, err := ParseMonitorQuery("disk where device_name = nvme0n1 and name = worker* and name_group = worker and process_name = writer and rwbs = *SM and cgroup.path = /apps/pg* and io.cgroup.path = /apps/logs*")
	if err != nil {
		t.Fatal(err)
	}
	ca, signer := testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	proof, err := signMonitor(signer, cert, []byte("nonce"), r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyMonitor(ca.PublicKey(), "admin", []byte("nonce"), proof); err != nil {
		t.Fatal(err)
	}
	proof.EventFilters["name"] = "other"
	if _, err := verifyMonitor(ca.PublicKey(), "admin", []byte("nonce"), proof); err == nil {
		t.Fatal("event filters not signed")
	}
}

func TestMultiAggregateSigning(t *testing.T) {
	r, err := ParseMonitorQuery("disk count, sum(sectors), percentile(sectors,95) over 30s by pid,device")
	if err != nil {
		t.Fatal(err)
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
	proof.Aggregation.Metrics[1].Field = "sector"
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
		t.Fatal("additional metric is not bound to signature")
	}
}

func TestPacketFilterSigning(t *testing.T) {
	ca, signer := testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	nonce := bytes.Repeat([]byte{'n'}, 32)
	req, err := signMonitor(signer, cert, nonce, MonitorRequest{Source: "packets", Packet: &PacketFilter{Protocol: "tcp", DestinationPort: 80}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, req); err != nil {
		t.Fatal(err)
	}
	req.Packet.DestinationPort = 443
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, req); err == nil {
		t.Fatal("modified packet filter passed authentication")
	}
}

func TestProbeSigning(t *testing.T) {
	r, err := ParseMonitorQuery(`syscalls where syscall > 1 { let process = pid; @x[process] = {calls: count(), total: sum(syscall)} } every 1s { emit @x; clear @x } after 3s { stop }`)
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
		func(r *MonitorRequest) { r.Aggregation.Ascending = true },
		func(r *MonitorRequest) { r.Comparisons[0].Value = "2" },
		func(r *MonitorRequest) { r.Comparisons[0].Op = ">=" },
		func(r *MonitorRequest) { r.Comparisons[0].Field = "pid" },
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
}

func TestSampleIntervalSigning(t *testing.T) {
	r, err := ParseMonitorQuery("memory avg(used) over 3s every 500ms")
	if err != nil {
		t.Fatal(err)
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

func TestStackShapeSigning(t *testing.T) {
	r, err := ParseMonitorQuery("syscalls where stacks = both and user.stack.offsets = false count over 1s by user.stack")
	if err != nil {
		t.Fatal(err)
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
	proof.Stacks.UserShape.Top = 3
	if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
		t.Fatal("stack shape not signed")
	}
}

func TestSymbolAndStackProofs(t *testing.T) {
	ca, signer := testSigner(t), testSigner(t)
	cert := testCertificate(t, signer, ca, "operator", "admin", time.Now().Add(time.Hour))
	nonce := []byte(strings.Repeat("s", 32))
	for _, r := range []MonitorRequest{
		{Source: "symbols", Mode: "snapshot", Symbols: &SymbolRequest{Target: "kernel", Addresses: []uint64{42}}},
		{Source: "syscalls", Stacks: &StackCapture{User: true}},
	} {
		proof, err := signMonitor(signer, cert, nonce, r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err != nil {
			t.Fatal(err)
		}
		if r.Symbols != nil {
			proof.Symbols = &SymbolRequest{Target: "kernel", Addresses: []uint64{43}}
		} else {
			proof.Stacks = &StackCapture{Kernel: true}
		}
		if _, err := verifyMonitor(ca.PublicKey(), "admin", nonce, proof); err == nil {
			t.Fatal("modified capture/lookup passed signature check")
		}
	}
}

func TestSymbolAndStackAuthorizationRequiresExplicitRoot(t *testing.T) {
	for _, request := range []MonitorRequest{
		{Source: "symbols"},
		{Source: "syscalls", Stacks: &StackCapture{User: true}},
		{Source: "tracepoint", Stacks: &StackCapture{Kernel: true}},
	} {
		if err := authorizeMonitorRequest(policy{"operator": {"65534": true}}, "operator", request); err == nil {
			t.Fatalf("accepted request without root policy: %+v", request)
		}
		err := authorizeMonitorRequest(policy{"operator": {"0": true}}, "operator", request)
		if os.Geteuid() == 0 && err != nil {
			t.Fatalf("explicit root authorization rejected: %v", err)
		}
		if os.Geteuid() != 0 && err == nil {
			t.Fatal("root policy alone authorized a non-root server")
		}
	}
}
