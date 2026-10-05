package portal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/relayserver"
	"golang.org/x/crypto/ssh"
)

func TestCapabilityReference(t *testing.T) {
	docs := describeCapabilities(policy{"reader": {"other-uid": true}}, "reader")
	if docs.Version != 1 || docs.OS != runtime.GOOS || docs.Arch != runtime.GOARCH || len(docs.Sources) != 14 || len(docs.Aggregates) != 9 {
		t.Fatalf("incomplete capability reference: %+v", docs)
	}
	if docs.Limits.AggregateMetrics != 8 {
		t.Fatal("multi-metric limit missing from capabilities")
	}
	for _, source := range docs.Sources {
		if source.Authorized || source.UnavailableReason == "" || len(source.Fields) == 0 {
			t.Errorf("unusable source needs a reason and schema: %+v", source)
		}
		for _, example := range source.Examples {
			r, err := ParseMonitorQuery(example)
			if err != nil || r.Source != source.Name {
				t.Fatalf("invalid documented example %q: %+v, %v", example, r, err)
			}
		}
		if source.Name == "syscalls" || source.Name == "tracepoint" {
			for _, path := range []string{"user_stack.capture_error_code", "kernel_stack.depth_limit_reached"} {
				if !slices.ContainsFunc(source.Fields, func(f FieldCapability) bool {
					return f.Path == path && !f.Aggregatable && f.Description != ""
				}) {
					t.Fatalf("stack diagnostic not documented: %s.%s", source.Name, path)
				}
			}
			for _, prefix := range []string{"user.stack", "kernel.stack"} {
				for _, suffix := range []string{"offsets", "top", "drop_bottom", "drop_top", "from", "until"} {
					if !slices.ContainsFunc(source.Filters, func(f FilterCapability) bool {
						return f.Field == prefix+"."+suffix && slices.Contains(f.Modes, "aggregate")
					}) {
						t.Fatalf("stack shape not discoverable: %s.%s", prefix, suffix)
					}
				}
			}
		}
		if source.Name == "cgroups" {
			for _, field := range []string{"io.read_bytes_per_second", "io.write_bytes_per_second", "io.discard_bytes_per_second", "io.read_ios_per_second", "io.write_ios_per_second", "io.discard_ios_per_second"} {
				if source.Sampling == nil || !slices.Contains(source.Sampling.NumericFields, field) {
					t.Fatalf("cgroup I/O rate not discoverable: %s", field)
				}
			}
			if slices.Contains(source.Sampling.NumericFields, "io.write_bytes") {
				t.Fatal("raw cgroup I/O counter advertised as a gauge")
			}
		}
		if slices.Contains(source.Modes, "aggregate") {
			for _, field := range []string{"result.format", "result.limit", "result.nonzero", "result.sort_metric"} {
				if !slices.ContainsFunc(source.Filters, func(f FilterCapability) bool { return f.Field == field && slices.Contains(f.Modes, "aggregate") }) {
					t.Fatalf("result control not discoverable: %s.%s", source.Name, field)
				}
			}
			r := MonitorRequest{Source: source.Name}
			if source.Name == "syscalls" || source.Name == "disk" {
				r.Phase = "completion"
			}
			r.Paths = source.Name == "syscalls"
			if source.Name == "syscalls" || source.Name == "tracepoint" {
				r.Stacks = &StackCapture{User: true, Kernel: true}
			}
			if source.Name == "tracepoint" {
				r.Tracepoint = &TracepointFilter{Event: "custom:sample", Fields: []string{"NAME"}}
			}
			for _, f := range source.GroupByFields {
				if err := (AggregationRequest{Window: 2 * time.Second, GroupBy: []string{f}}).validate(r); err != nil {
					t.Fatalf("documented group field %s.%s is rejected: %v", source.Name, f, err)
				}
			}
			for _, f := range source.NumericFields {
				if err := (AggregationRequest{Window: 2 * time.Second, Function: "sum", Field: f}).validate(r); err != nil {
					t.Fatalf("documented numeric field %s.%s is rejected: %v", source.Name, f, err)
				}
			}
		}
		if source.Sampling != nil {
			for _, field := range source.Sampling.GroupByFields {
				if _, err := ParseMonitorQuery(source.Name + " count over 2s every 100ms by " + field); err != nil {
					t.Fatalf("documented sampled group field %s.%s is rejected: %v", source.Name, field, err)
				}
			}
			for _, field := range source.Sampling.NumericFields {
				if _, err := ParseMonitorQuery(source.Name + " avg(" + field + ") over 2s every 100ms"); err != nil {
					t.Fatalf("documented sampled numeric field %s.%s is rejected: %v", source.Name, field, err)
				}
			}
		}
		switch source.Name {
		case "packets":
			if !slices.Contains(source.NumericFields, "length") || slices.Contains(source.NumericFields, "src.ip") {
				t.Fatal("packet lengths must be numeric, addresses must not be")
			}
			for _, field := range []FieldCapability{
				{Path: "packet.length", Type: "integer", QueryField: "length", Unit: "bytes", Aggregatable: true},
				{Path: "packet.data", Type: "base64"},
				{Path: "packet.destination_ip", Type: "string", QueryField: "dst.ip", Aggregatable: true},
				{Path: "packet.source_port", Type: "integer", QueryField: "src.port", Optional: true, Aggregatable: true},
			} {
				if !slices.Contains(source.Fields, field) {
					t.Fatalf("missing packet schema field: %+v", field)
				}
			}
		case "cpu":
			if !slices.Contains(source.Fields, FieldCapability{Path: "cpu[].name", Type: "string", QueryField: "name", Aggregatable: true}) ||
				!slices.Contains(source.Fields, FieldCapability{Path: "cpu[].idle", Type: "number", QueryField: "idle", Unit: "seconds", Aggregatable: true}) || source.Sampling == nil ||
				slices.Contains(source.Sampling.NumericFields, "idle") || !slices.Contains(source.Sampling.NumericFields, "utilization_percent") {
				t.Fatal("CPU raw counters must be separate from derived utilization")
			}
		case "gpu":
			if !slices.Contains(source.Fields, FieldCapability{Path: "gpus[].memory_used_mib", Type: "integer", QueryField: "memory_used_mib", Optional: true, Unit: "MiB", Aggregatable: true}) {
				t.Fatal("missing optional GPU metric units/type")
			}
		case "kernel":
			if !slices.Contains(source.Fields, FieldCapability{Path: "kernel.counters.processes_running", Type: "integer", QueryField: "counters.processes_running", Optional: true, Aggregatable: true}) {
				t.Fatal("missing nested optional kernel field")
			}
		}
	}
	for _, function := range []string{"count", "sum", "avg", "min", "max", "count_distinct", "percentile", "hist", "rate"} {
		if !slices.ContainsFunc(docs.Aggregates, func(a AggregateCapability) bool { return a.Name == function }) {
			t.Fatalf("missing aggregate %s", function)
		}
	}
	if docs.Limits.MaxWindow != "1h" || docs.Limits.Groups != 4096 || docs.Limits.GroupByFields != 4 || docs.Limits.RetainedAggregateValues != 65536 {
		t.Fatalf("incorrect limits: %+v", docs.Limits)
	}
	encoded, err := json.Marshal(docs)
	if err != nil || strings.Contains(string(encoded), "other-uid") {
		t.Fatalf("serialization failed or leaked policy: %v", err)
	}
	for _, query := range []string{"capabilities where name = foo", "capabilities count over 1s", "capabilities sum(length) over 1s"} {
		if _, err := ParseMonitorQuery(query); err == nil {
			t.Fatalf("accepted invalid capability query %q", query)
		}
	}
	if err := (MonitorRequest{Source: "capabilities"}).validate(); err == nil {
		t.Fatal("capabilities must not attach an event monitor")
	}
}

func TestClientCapabilities(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	relayHTTP := httptest.NewServer(relayserver.New())
	defer relayHTTP.Close()
	relayURL, err := netaddr.ParseRelayURL(relayHTTP.URL)
	if err != nil {
		t.Fatal(err)
	}
	server, err := iroh.Bind(ctx, iroh.WithALPNs(alpn), iroh.WithRelayMode(relay.ModeCustomURLs(relayURL)), iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	if err := server.Online(ctx); err != nil {
		t.Fatal(err)
	}
	coordinator := httptest.NewServer(NewCoordinator("secret"))
	defer coordinator.Close()
	reg := registration{Name: "node-a", EndpointID: server.ID().String(), RelayURL: relayURL.String()}
	if err := register(ctx, coordinator.URL, "secret", reg); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	ca := testSigner(t)
	cert := testCertificate(t, signer, ca, "reader", "admin", time.Now().Add(time.Hour))
	keyBlock, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath, certPath := filepath.Join(t.TempDir(), "key"), filepath.Join(t.TempDir(), "cert")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0600); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(filepath.Dir(keyPath), "ca.pub")
	if err := os.WriteFile(caPath, ssh.MarshalAuthorizedKey(ca.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	// reader may use another account, but NOT the server account or root.
	// Docs must still be readable without granting access to the data sources.
	p := policy{"reader": {"other-uid": true}, "operator": {fmt.Sprint(os.Geteuid()): true}}
	go serveWithSource(ctx, server, peerAuthenticator{ca: ca.PublicKey(), principal: "admin"}, p, func(context.Context, MonitorRequest, func(Event) error) error {
		t.Error("capability discovery must not attach an event source")
		return nil
	})
	client := Client{Name: "node-a", CoordinatorURL: coordinator.URL, KeyFile: keyPath, CertFile: certPath, CAFile: caPath}
	docs, err := client.Capabilities(ctx)
	if err != nil || docs.Version != 1 || len(docs.Sources) != 14 {
		t.Fatalf("capability request: %+v, %v", docs, err)
	}
	for _, source := range docs.Sources {
		if source.Authorized {
			t.Fatalf("reader wrongly authorized for %s", source.Name)
		}
	}
	if _, err := client.Query(ctx, MonitorRequest{Source: "process"}); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("discovery granted data access: %v", err)
	}
	snapshot, err := client.Query(ctx, MonitorRequest{Source: "capabilities"})
	if err != nil || snapshot.Capabilities == nil || snapshot.Source != "capabilities" || snapshot.Time.IsZero() {
		t.Fatalf("capabilities snapshot: %+v, %v", snapshot, err)
	}
	for _, identity := range []string{"unmapped", "operator"} {
		cert := testCertificate(t, signer, ca, identity, "admin", time.Now().Add(time.Hour))
		if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0600); err != nil {
			t.Fatal(err)
		}
		docs, err := client.Capabilities(ctx)
		if identity == "unmapped" {
			if err == nil || !strings.Contains(err.Error(), "not authorized") {
				t.Fatalf("unmapped identity: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			for _, source := range docs.Sources {
				if source.Name == "process" && !source.Authorized {
					t.Fatal("server-account identity should be authorized for process")
				}
			}
		}
	}
	bad := testCertificate(t, signer, testSigner(t), "reader", "admin", time.Now().Add(time.Hour))
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Capabilities(ctx); err == nil || !strings.Contains(err.Error(), "untrusted certificate authority") {
		t.Fatalf("untrusted certificate: %v", err)
	}
}

func TestCapabilityAggregationFlags(t *testing.T) {
	docs := describeCapabilities(nil, "reader")
	for _, source := range docs.Sources {
		for _, field := range source.Fields {
			if !field.Aggregatable {
				continue
			}
			groupable := slices.Contains(source.GroupByFields, field.QueryField)
			if source.Sampling != nil {
				groupable = groupable || slices.Contains(source.Sampling.GroupByFields, field.QueryField)
			}
			if field.QueryField == "" || !groupable {
				t.Fatalf("advertised aggregate field cannot be selected: %s.%s", source.Name, field.Path)
			}
			if strings.Contains(field.Path, "frames[]") || strings.HasPrefix(field.Path, "collection.") || strings.Contains(field.Path, "devices[]") {
				t.Fatalf("nested/diagnostic field incorrectly aggregatable: %s", field.Path)
			}
		}
		if source.Sampling == nil {
			continue
		}
		for _, field := range source.Sampling.Fields {
			if !field.Aggregatable {
				t.Fatalf("sampled scalar missing aggregate flag: %s.%s", source.Name, field.Path)
			}
			if field.Semantics == "counter" {
				query := source.Name + " rate(" + field.Path + ") over 2s every 100ms"
				if _, err := ParseMonitorQuery(query); err != nil {
					t.Fatalf("documented counter rate rejected: %s: %v", query, err)
				}
			}
		}
	}
}
