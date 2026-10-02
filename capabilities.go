package portal

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Capabilities is a versioned, server-generated query reference. Authorization
// is evaluated for the requesting certificate; runtime dependencies are not probed.
type Capabilities struct {
	Version     int                   `json:"version"`
	OS          string                `json:"os"`
	Arch        string                `json:"arch"`
	Syntax      string                `json:"syntax"`
	Notes       []string              `json:"notes"`
	Sources     []SourceCapability    `json:"sources"`
	Aggregates  []AggregateCapability `json:"aggregates"`
	Limits      CapabilityLimits      `json:"limits"`
	EventFields []FieldCapability     `json:"event_fields"`
}

type SourceCapability struct {
	Name              string              `json:"name"`
	Description       string              `json:"description"`
	Modes             []string            `json:"modes"` // events, snapshot, aggregate
	PlatformSupported bool                `json:"platform_supported"`
	Authorized        bool                `json:"authorized"`
	UnavailableReason string              `json:"unavailable_reason,omitempty"`
	Requirements      []string            `json:"requirements"`
	Fields            []FieldCapability   `json:"fields"`
	Filters           []FilterCapability  `json:"filters"`
	GroupByFields     []string            `json:"group_by_fields"`
	NumericFields     []string            `json:"numeric_fields"`
	Examples          []string            `json:"examples"`
	Sampling          *SamplingCapability `json:"sampling,omitempty"`
}

// FieldCapability describes an output JSON path, not necessarily a DSL field.
type FieldCapability struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	QueryField  string `json:"query_field,omitempty"` // DSL alias when filterable/groupable.
	Optional    bool   `json:"optional,omitempty"`
	Unit        string `json:"unit,omitempty"`
	Description string `json:"description,omitempty"`
}

type FilterCapability struct {
	Field       string   `json:"field"`
	Type        string   `json:"type"`
	Operators   []string `json:"operators"`
	Values      []string `json:"values,omitempty"`
	Modes       []string `json:"modes"`
	Description string   `json:"description"`
}

type AggregateCapability struct {
	Name        string `json:"name"`
	Syntax      string `json:"syntax"`
	FieldType   string `json:"field_type"` // none, scalar, number (event metrics remain integers)
	Description string `json:"description"`
}

type CapabilityLimits struct {
	QueryBytes              int    `json:"query_bytes"`
	MaxWindow               string `json:"max_window"`
	GroupByFields           int    `json:"group_by_fields"`
	Groups                  int    `json:"groups"`
	RetainedAggregateValues int    `json:"retained_aggregate_values"`
	TracepointFields        int    `json:"tracepoint_fields"`
	SyscallFilters          int    `json:"syscall_filters"`
	PacketCaptureBytes      int    `json:"packet_capture_bytes"`
	DefaultMonitorTTL       string `json:"default_monitor_ttl"`
	RegisteredMonitors      int    `json:"registered_monitors"`
	MonitorRingEvents       int    `json:"monitor_ring_events"`
	MonitorEventBytes       int    `json:"monitor_event_bytes"`
}

// Capabilities requests the server's reference using the signed query protocol.
func (c Client) Capabilities(ctx context.Context) (Capabilities, error) {
	snapshot, err := c.Query(ctx, MonitorRequest{Source: "capabilities"})
	if err != nil {
		return Capabilities{}, err
	}
	if snapshot.Capabilities == nil {
		return Capabilities{}, errors.New("server returned no capabilities")
	}
	return *snapshot.Capabilities, nil
}

// outputFields derives paths and types from the actual wire structs so adding
// or renaming a response field also updates the capability reference.
func outputFields(value any, prefix string) []FieldCapability {
	var fields []FieldCapability
	var visit func(reflect.Type, string, bool)
	visit = func(typ reflect.Type, path string, optional bool) {
		if typ.Kind() == reflect.Pointer {
			visit(typ.Elem(), path, true)
			return
		}
		if typ == reflect.TypeOf(time.Time{}) {
			fields = append(fields, FieldCapability{Path: path, Type: "timestamp", Optional: optional, Description: "RFC3339 UTC timestamp"})
			return
		}
		if typ.Kind() == reflect.Struct {
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				tag := strings.Split(f.Tag.Get("json"), ",")
				if tag[0] == "" || tag[0] == "-" {
					continue
				}
				name := tag[0]
				if path != "" {
					name = path + "." + name
				}
				visit(f.Type, name, optional || strings.Contains(f.Tag.Get("json"), ",omitempty"))
			}
			return
		}
		if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Struct {
			visit(typ.Elem(), path+"[]", optional)
			return
		}
		kind := "integer"
		switch typ.Kind() {
		case reflect.String:
			kind = "string"
		case reflect.Float32, reflect.Float64:
			kind = "number"
		case reflect.Slice:
			kind = "array<string>"
			if typ.Elem().Kind() == reflect.Uint8 {
				kind = "base64"
			}
		case reflect.Map:
			kind = "object<integer>"
		}
		fields = append(fields, FieldCapability{Path: path, Type: kind, Optional: optional})
	}
	visit(reflect.TypeOf(value), prefix, false)
	return fields
}

func describeCapabilities(p policy, cert *ssh.Certificate) Capabilities {
	events := []string{"events", "aggregate"}
	snapshot := []string{"snapshot"}
	processModes := []string{"events", "snapshot", "aggregate"}
	filter := func(field, typ, description string, modes []string, values ...string) FilterCapability {
		return FilterCapability{Field: field, Type: typ, Operators: []string{"="}, Values: values, Modes: modes, Description: description}
	}
	nameFilter := func(modes []string) FilterCapability {
		return filter("name", "string", "Exact name, prefix*, or *suffix; one edge wildcard only, case-sensitive; * alone is invalid.", modes)
	}
	pidFilter := filter("pid", "integer", "Process ID, 1–4294967295.", events)
	pidFilter.Modes = processModes
	syscall := filter("syscall", "integer", "Architecture-specific syscall number, 0–65535; in accepts up to 256 numbers.", events)
	syscall.Operators = []string{"=", "in"}
	selected := filter("fields", "string", "Required selection of 1–16 scalar integer field names from the kernel tracepoint format; names are case-sensitive.", events)
	selected.Operators = []string{"in"}
	sources := []SourceCapability{
		{Name: "syscalls", Description: "Linux eBPF syscall entry attempts, not completions. Non-root servers expose only their account; root servers expose all accounts.", Modes: events, Requirements: []string{"Linux eBPF raw tracepoint and ring buffer permissions"}, Fields: []FieldCapability{{Path: "pid", Type: "integer"}, {Path: "tid", Type: "integer"}, {Path: "syscall", Type: "integer"}}, Filters: []FilterCapability{filter("pid", "integer", "Process/thread-group ID, 1–4294967295.", events), syscall}, Examples: []string{"syscalls count over 30s by pid"}},
		{Name: "process", Description: "Process snapshots with best-effort resource metrics, plus lifecycle changes polled once per second. Short-lived processes may be missed. Non-root servers see their own account; root sees all accounts on Unix. Windows is restricted to the server account.", Modes: processModes, Fields: append(outputFields(ProcessEvent{}, "process"), append(outputFields(ProcessInfo{}, "processes[]"), FieldCapability{Path: "pid", Type: "integer"})...), Filters: []FilterCapability{pidFilter, nameFilter(processModes), filter("action", "string", "Lifecycle action; not valid in snapshots.", events, "start", "exit")}, Examples: []string{"process where name = worker*", "process where action = start count over 1m by name"}},
		{Name: "packets", Description: "Linux eBPF AF_PACKET capture of TCP/UDP over IPv4/IPv6, with up to two VLAN tags. No TCP reassembly. Packet length is Ethernet/VLAN plus the declared IP packet size, excluding trailing padding/FCS; raw data is capped at 2048 bytes. Retransmissions and observations on multiple interfaces count separately.", Modes: events, Requirements: []string{"root server and explicit root policy authorization (also permits root commands)", "Linux eBPF socket-filter permissions and CAP_NET_RAW"}, Fields: outputFields(PacketEvent{}, "packet"), Filters: []FilterCapability{filter("protocol", "string", "Required when filtering ports.", events, "tcp", "udp"), filter("direction", "string", "Relative to the capture interface.", events, "incoming", "outgoing"), filter("src.ip", "IP address", "Exact IPv4 or IPv6 address; no CIDR.", events), filter("dst.ip", "IP address", "Exact IPv4 or IPv6 address; no CIDR.", events), filter("src.port", "integer", "Source port, 1–65535; requires protocol.", events), filter("dst.port", "integer", "Destination port, 1–65535; requires protocol.", events)}, Examples: []string{"packets where protocol = tcp and dst.port = 80 sum(length) over 30s by src.ip, dst.ip"}},
		{Name: "disk", Description: "Linux block:block_rq_issue requests, not completions. No filesystem path or application PID. Sector values use 512-byte units.", Modes: events, Requirements: []string{"root server and explicit root policy authorization (also permits root commands)", "Linux eBPF tracepoint permissions and readable block:block_rq_issue format"}, Fields: outputFields(DiskEvent{}, "disk"), Filters: []FilterCapability{filter("device", "integer", "Nonzero kernel device ID, decimal or 0x hex, up to 4294967295.", events), filter("operation", "string", "Request operation; output may also contain other.", events, "read", "write", "discard", "flush")}, Examples: []string{"disk where operation = write percentile(sectors, 95) over 1m by device"}},
		{Name: "tracepoint", Description: "Selected integer fields from a named Linux tracepoint. Pointer, array, bitfield and dynamic fields are rejected. field.NAME refers to a selected field for filters, grouping and aggregation. No arbitrary eBPF programs are accepted.", Modes: events, Requirements: []string{"root server and explicit root policy authorization (also permits root commands)", "Linux eBPF tracepoint/ring buffer permissions and readable kernel tracefs format"}, Fields: outputFields(TracepointEvent{}, "tracepoint"), Filters: []FilterCapability{filter("event", "string", "Required category:name tracepoint identifier.", events), selected, filter("field.NAME", "integer", "Equality on a selected field; signed decimal or unsigned decimal/0x hex, up to 64 bits. Applied after eBPF capture.", events)}, GroupByFields: []string{"field.NAME"}, NumericFields: []string{"field.NAME"}, Examples: []string{"tracepoint where event = sched:sched_wakeup and fields in (common_pid, target_cpu) count over 30s by field.target_cpu"}},
		{Name: "cpu", Description: "Per-CPU cumulative accounting, not instantaneous utilization percentages.", Modes: snapshot, Fields: outputFields([]CPUInfo{}, "cpu"), Examples: []string{"cpu"}},
		{Name: "memory", Description: "Current RAM and swap usage.", Modes: snapshot, Fields: outputFields(MemoryInfo{}, "memory"), Examples: []string{"memory"}},
		{Name: "network", Description: "Interfaces, addresses and cumulative traffic counters, not rates.", Modes: snapshot, Fields: outputFields([]InterfaceInfo{}, "network"), Filters: []FilterCapability{nameFilter(snapshot)}, Examples: []string{"network where name = eth*"}},
		{Name: "kernel", Description: "Boot time, uptime, load averages and optional Linux scheduling counters.", Modes: snapshot, Fields: outputFields(KernelInfo{}, "kernel"), Examples: []string{"kernel"}},
		{Name: "sensors", Description: "Host-exposed temperature sensors; may legitimately be empty.", Modes: snapshot, Fields: outputFields([]SensorInfo{}, "sensors"), Filters: []FilterCapability{nameFilter(snapshot)}, Examples: []string{"sensors"}},
		{Name: "containers", Description: "Docker container metadata, not container events.", Modes: snapshot, Requirements: []string{"Linux, readable /var/run/docker.sock", "root server and explicit root policy authorization (also permits root commands)"}, Fields: outputFields([]ContainerInfo{}, "containers"), Filters: []FilterCapability{nameFilter(snapshot)}, Examples: []string{"containers where name = web*"}},
		{Name: "cgroups", Description: "Linux cgroup v2 resource accounting from the visible /sys/fs/cgroup hierarchy. Usage includes descendants: summing parents and children double-counts usage. Limits are local configuration, not effective ancestor/cpuset limits. Unlimited or unavailable limits are omitted.", Modes: snapshot, Requirements: []string{"Linux cgroup v2 mounted at /sys/fs/cgroup with readable controller files", "root server and explicit root policy authorization (also permits root commands)"}, Fields: outputFields([]CgroupInfo{}, "cgroups"), Filters: []FilterCapability{filter("path", "string", "Path relative to the visible mount, beginning with /; exact, prefix*, or *suffix, not a shell glob or filesystem path.", snapshot)}, Examples: []string{"cgroups", "cgroups where path = /system.slice/*"}},
		{Name: "gpu", Description: "Nvidia GPU metrics; unavailable optional metrics are omitted.", Modes: snapshot, Requirements: []string{"nvidia-smi on the server PATH and an Nvidia driver"}, Fields: outputFields([]GPUInfo{}, "gpus"), Filters: []FilterCapability{nameFilter(snapshot)}, Examples: []string{"gpu"}},
	}
	for i := range sources {
		s := &sources[i]
		if _, ok := sampledSources[s.Name]; ok {
			groups, numeric := sampledFields(s.Name)
			s.Sampling = &SamplingCapability{DefaultInterval: DefaultSampleInterval.String(), MinInterval: MinSampleInterval.String(), Fields: snapshotSampleFields(s.Name), GroupByFields: groups, NumericFields: numeric}
			if !slices.Contains(s.Modes, "aggregate") {
				s.Modes = append(append([]string{}, s.Modes...), "aggregate")
			}
			s.Examples = append(s.Examples, s.Name+" count over 30s every 1s")
			switch s.Name {
			case "cpu":
				s.Examples = append(s.Examples, "cpu avg(utilization_percent) over 30s every 1s by name")
			case "memory":
				s.Examples = append(s.Examples, "memory avg(used) over 30s every 1s")
			case "network":
				s.Examples = append(s.Examples, "network avg(bytes_recv_per_second) over 30s every 1s by name")
			case "sensors":
				s.Examples = append(s.Examples, "sensors max(temperature_celsius) over 30s every 1s by name")
			case "gpu":
				s.Examples = append(s.Examples, "gpu avg(utilization_percent) over 30s every 1s by uuid")
			case "process":
				s.Examples = append(s.Examples, "process avg(cpu_percent) over 5s every 1s by pid,name", "process max(rss_bytes) over 5s every 1s by pid,name")
			case "cgroups":
				s.Examples = append(s.Examples, "cgroups avg(cpu_percent) over 30s every 1s by path", "cgroups max(memory_bytes) over 30s every 1s by path")
			}
		}
		s.PlatformSupported = true
		if s.Name == "syscalls" || s.Name == "packets" || s.Name == "disk" || s.Name == "tracepoint" || s.Name == "containers" || s.Name == "cgroups" {
			s.PlatformSupported = runtime.GOOS == "linux"
		}
		// Authorization is the same check used by real requests, independent
		// of platform support and unprobed runtime dependencies.
		err := authorizeMonitorSource(p, cert, s.Name)
		s.Authorized = err == nil
		if !s.PlatformSupported {
			s.UnavailableReason = "requires Linux"
		} else if err != nil {
			s.UnavailableReason = err.Error()
		}
		if s.Filters == nil {
			s.Filters = []FilterCapability{}
		}
		if sampledAggregation(MonitorRequest{Source: s.Name}) {
			for j := range s.Filters {
				s.Filters[j].Modes = []string{"snapshot", "aggregate"}
			}
		}
		if s.Requirements == nil {
			s.Requirements = []string{}
		}
		if s.Name != "tracepoint" {
			s.GroupByFields, s.NumericFields, _ = aggregateFields(MonitorRequest{Source: s.Name})
		}
		if s.GroupByFields == nil {
			s.GroupByFields = []string{}
		}
		if s.NumericFields == nil {
			s.NumericFields = []string{}
		}
		for j := range s.Fields {
			f := &s.Fields[j]
			alias := f.Path[strings.LastIndex(f.Path, ".")+1:]
			if s.Name == "packets" {
				switch alias {
				case "source_ip":
					alias = "src.ip"
				case "destination_ip":
					alias = "dst.ip"
				case "source_port":
					alias = "src.port"
				case "destination_port":
					alias = "dst.port"
				}
			}
			if slices.Contains(s.GroupByFields, alias) || slices.ContainsFunc(s.Filters, func(filter FilterCapability) bool { return filter.Field == alias }) {
				f.QueryField = alias
			}
			switch {
			case s.Name == "memory" || strings.HasSuffix(f.Path, "bytes_sent") || strings.HasSuffix(f.Path, "bytes_recv") || strings.HasSuffix(f.Path, "_bytes") || f.Path == "packet.length":
				f.Unit = "bytes"
			case f.Path == "disk.sector" || f.Path == "disk.sectors":
				f.Unit = "512-byte sectors"
			case s.Name == "cpu" && !strings.HasSuffix(f.Path, ".name") || f.Path == "kernel.uptime_seconds" || strings.HasSuffix(f.Path, ".cpu_seconds"):
				f.Unit = "seconds"
			case f.Path == "cgroups[].cpu_limit_cores":
				f.Unit = "cores"
			case f.Path == "cgroups[].pids_current":
				f.Unit = "tasks"
			case f.Path == "processes[].threads":
				f.Unit = "threads"
			case f.Path == "processes[].command_line":
				f.Description = "Best-effort command line; may contain secrets. Process metrics require the existing process-source authorization."
			case strings.HasSuffix(f.Path, "_celsius"):
				f.Unit = "degrees Celsius"
			case strings.HasSuffix(f.Path, "_percent"):
				f.Unit = "percent"
			case strings.HasSuffix(f.Path, "_mib"):
				f.Unit = "MiB"
			case strings.HasSuffix(f.Path, "_watts"):
				f.Unit = "watts"
			}
		}
	}
	return Capabilities{
		Version: 1, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Syntax: "SOURCE [where FIELD = VALUE [and ...]] [FUNCTION over DURATION [every INTERVAL] [by FIELD, ...]]; count | FUNCTION(FIELD) | percentile(FIELD, PERCENT); syscall in (N, ...) and tracepoint fields in (NAME, ...)",
		Notes: []string{
			"Modes: events uses monitor/monitor-register; snapshot and aggregate use query. process without an aggregate is a snapshot in query and events in monitor.",
			"Platform support and authorization are reported separately. Runtime dependencies are not probed; queries can still fail due to kernel permissions, unsupported formats, missing tools or hardware.",
			"All sources require a valid CA-signed certificate with the configured principal. Except capabilities, authorization requires access to the server account; privileged sources additionally require root. Root authorization also permits arbitrary root commands.",
			"Filters use AND only; no OR, comparisons, regex or interior globs. Source/field keywords are case-insensitive except kernel field names and name values. Quote values containing spaces.",
			"Aggregation collects a fresh half-open server-ingestion window [start,end), not registered-monitor history. One function per query; no repeating windows. Capture is best-effort; cancellation stops collection and source failures return errors.",
			"Sources with sampling metadata support sampled snapshot aggregates. every defaults to 1s for snapshot-only sources; process requires explicit every to select snapshots instead of lifecycle events. Sampling fields are record-relative paths, not event field aliases.",
			"Samples are collected immediately and on the interval grid before the window ends; slow reads skip ticks without overlap. count counts observed records. avg is an arithmetic sample mean, not time-weighted; sum of a gauge is a sum of observations, not an integral. Missing optional metrics are skipped, not zero.",
			"Raw counters cannot be summed/averaged/minimized/maximized/percentiled. Use FIELD_per_second for rates, or CPU utilization_percent. Derived values require consecutive observations, so the first observation is only a baseline. Resets, disappearing/reappearing entities, and missing fields start a new baseline; no zero is fabricated. A derived query needs a window longer than its interval.",
			"Process snapshots include best-effort CPU seconds, RSS/virtual memory bytes, user, state, threads and command line. Unavailable values are omitted. Sampled process cpu_percent is 100 × delta cpu_seconds / elapsed seconds, excluding children: 100% is one busy core and multithreaded processes may exceed 100%. PID/start time identifies observations so PID reuse restarts the baseline.",
			"Group/numeric field names are DSL aliases: src.ip/dst.ip map to packet.source_ip/destination_ip; src.port/dst.port map to packet.source_port/destination_port; name/action map to process.name/action; field.NAME maps to tracepoint.fields.NAME.",
			"Event time is UTC receipt time. tai64n is the resumable registered-monitor cursor. Registered monitors survive disconnects, not server restarts; bounded storage can overwrite old events. Reads reset the idle TTL.",
		},
		Sources: sources,
		Aggregates: []AggregateCapability{
			{"count", "count over DURATION [every INTERVAL] [by FIELD, ...]", "none", "Number of matching events or observed snapshot records; no field argument."},
			{"sum", "sum(FIELD) over DURATION [every INTERVAL] [by FIELD, ...]", "number", "Sum; integers remain exact, decimal results round to 18 places. Empty ungrouped window returns 0."},
			{"avg", "avg(FIELD) over DURATION [every INTERVAL] [by FIELD, ...]", "number", "Arithmetic sample mean rounded to 18 decimal places, not time-weighted; empty ungrouped window returns null."},
			{"min", "min(FIELD) over DURATION [every INTERVAL] [by FIELD, ...]", "number", "Minimum; empty ungrouped window returns null."},
			{"max", "max(FIELD) over DURATION [every INTERVAL] [by FIELD, ...]", "number", "Maximum; empty ungrouped window returns null."},
			{"count_distinct", "count_distinct(FIELD) over DURATION [every INTERVAL] [by FIELD, ...]", "scalar", "Exact distinct count of any groupable field, including strings; empty ungrouped window returns 0."},
			{"percentile", "percentile(FIELD, PERCENT) over DURATION [every INTERVAL] [by FIELD, ...]", "number", "Exact nearest-rank percentile of samples; finite PERCENT from 0 to 100 inclusive; empty ungrouped window returns null."},
		},
		Limits:      CapabilityLimits{QueryBytes: 4096, MaxWindow: "1h", GroupByFields: 4, Groups: maxAggregateGroups, RetainedAggregateValues: maxAggregateValues, TracepointFields: 16, SyscallFilters: 256, PacketCaptureBytes: 2048, DefaultMonitorTTL: DefaultMonitorTTL.String(), RegisteredMonitors: maxRegisteredMonitors, MonitorRingEvents: monitorRingSize, MonitorEventBytes: maxMonitorEventSize},
		EventFields: []FieldCapability{{Path: "time", Type: "timestamp", Description: "UTC receipt time"}, {Path: "tai64n", Type: "string", Description: "TAI64N timestamp/cursor for resuming monitor reads"}},
	}
}
