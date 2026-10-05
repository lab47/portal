package portal

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"
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
	AggregateMetrics        int    `json:"aggregate_metrics"`
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

func describeCapabilities(p policy, identity string) Capabilities {
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
	syscall := filter("syscall", "integer or :name", "Numeric ID (0–65535) or case-sensitive Linux name such as :fsync; in accepts up to 256 mixed IDs/names. Names resolve on the server's native ABI, not the client. Name tables support amd64, arm64, 386 and arm; unknown names/unsupported architectures are rejected. Compatibility ABIs are not translated. API uses syscall_names without the colon; output syscall remains numeric.", events)
	syscall.Operators = []string{"=", "in"}
	selected := filter("fields", "string", "Original DSL requires 1–16 scalar integer fields; selector/action syntax infers field.NAME references from predicates/actions and unions them with explicit selection (maximum 16). Count/identity/stack-only actions select no payload fields. Names are case-sensitive; kernel format restrictions remain.", events)
	selected.Operators = []string{"in"}
	rootQueryRequirement := "root server and root query authorization via certificate policy, account SSH keys, or query-authorized-keys"
	sources := []SourceCapability{
		{Name: "syscalls", Description: "Linux eBPF syscall entries (default), or paired completions with entry stacks and monotonic elapsed duration. Non-root servers expose only their account; root servers expose all accounts.", Modes: events, Requirements: []string{"Linux eBPF raw tracepoint and ring buffer permissions"}, Fields: []FieldCapability{{Path: "pid", Type: "integer"}, {Path: "tid", Type: "integer"}, {Path: "syscall", Type: "integer"}}, Filters: []FilterCapability{filter("pid", "integer", "Process/thread-group ID, 1–4294967295.", events), syscall}, Examples: []string{"syscalls count over 30s by pid"}},
		{Name: "process", Description: "Process snapshots with best-effort resource metrics, plus lifecycle changes polled once per second. Short-lived processes may be missed. Non-root servers see their own account; root sees all accounts on Unix. Windows is restricted to the server account.", Modes: processModes, Fields: append(outputFields(ProcessEvent{}, "process"), append(outputFields(ProcessInfo{}, "processes[]"), FieldCapability{Path: "pid", Type: "integer"})...), Filters: []FilterCapability{pidFilter, nameFilter(processModes), filter("action", "string", "Lifecycle action; not valid in snapshots.", events, "start", "exit")}, Examples: []string{"process where name = worker*", "process where action = start count over 1m by name"}},
		{Name: "packets", Description: "Linux eBPF AF_PACKET capture of TCP/UDP over IPv4/IPv6, with up to two VLAN tags. No TCP reassembly. Packet length is Ethernet/VLAN plus the declared IP packet size, excluding trailing padding/FCS; raw data is capped at 2048 bytes. Retransmissions and observations on multiple interfaces count separately.", Modes: events, Requirements: []string{rootQueryRequirement, "Linux eBPF socket-filter permissions and CAP_NET_RAW"}, Fields: outputFields(PacketEvent{}, "packet"), Filters: []FilterCapability{filter("protocol", "string", "Required when filtering ports.", events, "tcp", "udp"), filter("direction", "string", "Relative to the capture interface.", events, "incoming", "outgoing"), filter("src.ip", "IP address", "Exact IPv4 or IPv6 address; no CIDR.", events), filter("dst.ip", "IP address", "Exact IPv4 or IPv6 address; no CIDR.", events), filter("src.port", "integer", "Source port, 1–65535; requires protocol.", events), filter("dst.port", "integer", "Destination port, 1–65535; requires protocol.", events)}, Examples: []string{"packets where protocol = tcp and dst.port = 80 sum(length) over 30s by src.ip, dst.ip"}},
		{Name: "disk", Description: "Linux block:block_rq_issue requests, not completions. No filesystem path or application PID. Sector values use 512-byte units.", Modes: events, Requirements: []string{rootQueryRequirement, "Linux eBPF tracepoint permissions and readable block:block_rq_issue format"}, Fields: outputFields(DiskEvent{}, "disk"), Filters: []FilterCapability{filter("device", "integer", "Nonzero kernel device ID, decimal or 0x hex, up to 4294967295.", events), filter("operation", "string", "Request operation; output may also contain other.", events, "read", "write", "discard", "flush")}, Examples: []string{"disk where operation = write percentile(sectors, 95) over 1m by device"}},
		{Name: "tracepoint", Description: "Selected integer fields from a named Linux tracepoint. Pointer, array, bitfield and dynamic fields are rejected. field.NAME refers to a selected field for filters, grouping and aggregation. No arbitrary eBPF programs are accepted.", Modes: events, Requirements: []string{rootQueryRequirement, "Linux eBPF tracepoint/ring buffer permissions and readable kernel tracefs format"}, Fields: outputFields(TracepointEvent{}, "tracepoint"), Filters: []FilterCapability{filter("event", "string", "Required category:name tracepoint identifier.", events), selected, filter("field.NAME", "integer", "Equality on a selected field; signed decimal or unsigned decimal/0x hex, up to 64 bits. Applied after eBPF capture.", events)}, GroupByFields: []string{"field.NAME"}, NumericFields: []string{"field.NAME"}, Examples: []string{"tracepoint where event = sched:sched_wakeup and fields in (common_pid, target_cpu) count over 30s by field.target_cpu"}},
		{Name: "cpu", Description: "Per-CPU cumulative accounting, not instantaneous utilization percentages.", Modes: snapshot, Fields: outputFields([]CPUInfo{}, "cpu"), Examples: []string{"cpu"}},
		{Name: "memory", Description: "Current RAM and swap usage.", Modes: snapshot, Fields: outputFields(MemoryInfo{}, "memory"), Examples: []string{"memory"}},
		{Name: "network", Description: "Interfaces, addresses and cumulative traffic counters, not rates.", Modes: snapshot, Fields: outputFields([]InterfaceInfo{}, "network"), Filters: []FilterCapability{nameFilter(snapshot)}, Examples: []string{"network where name = eth*"}},
		{Name: "kernel", Description: "Boot time, uptime, load averages and optional Linux scheduling counters.", Modes: snapshot, Fields: outputFields(KernelInfo{}, "kernel"), Examples: []string{"kernel"}},
		{Name: "sensors", Description: "Host-exposed temperature sensors; may legitimately be empty.", Modes: snapshot, Fields: outputFields([]SensorInfo{}, "sensors"), Filters: []FilterCapability{nameFilter(snapshot)}, Examples: []string{"sensors"}},
		{Name: "containers", Description: "Docker container metadata, not container events.", Modes: snapshot, Requirements: []string{"Linux, readable /var/run/docker.sock", rootQueryRequirement}, Fields: outputFields([]ContainerInfo{}, "containers"), Filters: []FilterCapability{nameFilter(snapshot)}, Examples: []string{"containers where name = web*"}},
		{Name: "cgroups", Description: "Linux cgroup v2 CPU, memory, task and io.stat accounting from the visible /sys/fs/cgroup hierarchy. io contains cumulative read/write/discard bytes and operations, plus per-device major:minor counters retaining kernel keys. Missing io.stat omits io; empty io.stat has zero totals. Incomplete per-device fields omit that total. Sampled aggregates expose total *_per_second rates, not per-device rows. Usage includes descendants: summing parents and children double-counts usage. I/O attribution depends on kernel/filesystem cgroup writeback support, not exact syscall or flush accounting. Limits are local configuration, not effective ancestor/cpuset limits. Unlimited or unavailable limits are omitted.", Modes: snapshot, Requirements: []string{"Linux cgroup v2 mounted at /sys/fs/cgroup with readable controller files", rootQueryRequirement}, Fields: outputFields([]CgroupInfo{}, "cgroups"), Filters: []FilterCapability{filter("path", "string", "Path relative to the visible mount, beginning with /; exact, prefix*, or *suffix, not a shell glob or filesystem path.", snapshot)}, Examples: []string{"cgroups", "cgroups where path = /system.slice/*", "cgroups avg(io.read_bytes_per_second), avg(io.write_bytes_per_second) over 30s every 1s by path"}},
		{Name: "gpu", Description: "Nvidia GPU metrics; unavailable optional metrics are omitted.", Modes: snapshot, Requirements: []string{"nvidia-smi on the server PATH and an Nvidia driver"}, Fields: outputFields([]GPUInfo{}, "gpus"), Filters: []FilterCapability{nameFilter(snapshot)}, Examples: []string{"gpu"}},
		{Name: "symbols", Description: "Server-side ELF, process mapping and kernel symbol lookup. Process name searches cover executable file mappings and return runtime addresses; unreadable objects fail the query. Addresses are exact hexadecimal strings in results. No DWARF, demangling or JIT resolution.", Modes: snapshot, Requirements: []string{"Linux, readable ELF/process mappings or unrestricted kallsyms", rootQueryRequirement}, Fields: outputFields(SymbolResult{}, "symbols"), Filters: []FilterCapability{filter("target", "string", "Required target.", snapshot, "kernel", "process", "binary"), filter("pid", "integer", "Required for process name or address lookup.", snapshot), filter("path", "string", "Absolute server-side ELF path for binary target.", snapshot), filter("name", "string", "Exact or edge glob; mutually exclusive with addresses. Process searches include the executable and mapped libraries.", snapshot), {Field: "addresses", Type: "integer", Operators: []string{"in"}, Modes: snapshot, Description: "1–256 unsigned 64-bit decimal/hex addresses; runtime addresses for kernel/process, link-time addresses for binary."}, filter("limit", "integer", "Name matches: default 256, maximum 4096 across all objects.", snapshot)}, Examples: []string{"symbols where target = kernel and name = vfs_*", "symbols where target = process and pid = 1234 and name = handle*"}},
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
		if s.Name == "syscalls" || s.Name == "packets" || s.Name == "disk" || s.Name == "tracepoint" || s.Name == "containers" || s.Name == "cgroups" || s.Name == "symbols" {
			s.PlatformSupported = runtime.GOOS == "linux"
		}
		// Authorization is the same check used by real requests, independent
		// of platform support and unprobed runtime dependencies.
		err := authorizeMonitorSource(p, identity, s.Name)
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
		if s.Name == "syscalls" {
			s.Filters = append(s.Filters, filter("phase", "string", "entry is the default; completion emits only paired exits. duration_ns/return_value require completion. Completion needs readable raw_syscalls:sys_exit format and sched_process_exit.", events, "entry", "completion"))
			s.Filters = append(s.Filters, filter("paths", "boolean", "Opt-in kernel FD path capture at syscall entry for fsync/fdatasync, read/write, vectored/positional variants, ftruncate and fallocate; retained through completion so later close/reuse does not affect it. Best-effort walk relative to process root, up to 32 steps and 256 encoded component bytes; errors instead of truncation. Concurrent rename/FD-table changes may race. Requires native 64-bit syscall ABI, runtime BTF and readable raw_syscalls:sys_enter format.", events, "true", "false"))
			s.Fields = append(s.Fields, outputFields(SyscallFile{}, "file")...)
			s.Fields = append(s.Fields, FieldCapability{Path: "file.dir", Type: "string", QueryField: "file.dir", Optional: true, Description: "Aggregation-only projection: POSIX parent directory of captured file.path; optionally truncated to file.depth components."})
			s.Filters = append(s.Filters, filter("file.depth", "integer", "Aggregate file.dir prefix depth from process root, 0–32; zero keeps the full directory. Requires paths=true. Does not change raw paths.", []string{"aggregate"}))
			s.Fields = append(s.Fields, FieldCapability{Path: "phase", Type: "string"}, FieldCapability{Path: "duration_ns", Type: "integer", Optional: true, Unit: "nanoseconds", Description: "Completion only; caller elapsed time including scheduling and waits, not pure disk time."}, FieldCapability{Path: "return_value", Type: "integer", Optional: true, Description: "Completion only; signed kernel return value, including negative errno."})
			s.Examples = append(s.Examples, "syscalls where phase = completion and syscall in (:fsync,:fdatasync) and stacks = user sum(duration_ns) over 30s by pid, name, user.stack")
			s.Examples = append(s.Examples, "syscalls where phase = completion and paths = true and syscall in (:fsync,:fdatasync) count, sum(duration_ns) over 30s by pid, file.path")
			s.Examples = append(s.Examples, "syscalls where phase = completion and paths = true and file.depth = 3 and syscall in (:fsync,:fdatasync) count, sum(duration_ns) over 30s by cgroup.path, process_name, file.dir")
			s.Examples = append(s.Examples, `syscalls where phase = completion and stacks = user and user.stack.from in ("os.(*File).Sync", '*Fdatasync') count over 30s by user.stack`)
		}
		if s.Name == "disk" {
			s.Description = "Linux block request issues by default, or pointer-paired completions with monotonic duration_ns. Identity is the issuing task, not necessarily the application responsible for asynchronous writeback. Sectors use 512-byte units."
			s.Filters = append(s.Filters, filter("phase", "string", "entry is the default. completion requires runtime kernel BTF and supported block tracepoint/request layouts; fails explicitly otherwise. Duration is latest issue to final byte completion, excluding pre-issue queue time. Partial completions produce one final event, preserving any nonzero block status. Reissues reset the timestamp and issuing identity. Bounded pending requests and loss counters are subscription-wide.", events, "entry", "completion"))
			s.Examples = append(s.Examples, "disk where phase = completion count, avg(duration_ns), percentile(duration_ns,95) over 30s by device, pid, name")
			s.Examples = append(s.Examples, "disk where operation = write count, sum(sectors) over 30s by device_name, io.cgroup.path")
			for _, field := range []string{"device_name", "rwbs", "io.cgroup.path"} {
				s.Filters = append(s.Filters, filter(field, "string", "Exact value or one edge glob. Applied server-side after capture, not inside eBPF; unavailable metadata does not match.", events))
			}
		}
		if s.Name != "tracepoint" {
			r := MonitorRequest{Source: s.Name}
			if s.Name == "syscalls" || s.Name == "disk" {
				r.Phase = "completion"
			}
			r.Paths = s.Name == "syscalls"
			s.GroupByFields, s.NumericFields, _ = aggregateFields(r)
		} else {
			s.GroupByFields = append(s.GroupByFields, "pid", "tid", "name", "process_name", "name_group", "cgroup.path")
			s.NumericFields = append(s.NumericFields, "pid", "tid")
		}
		if slices.Contains(s.Modes, "events") {
			for _, field := range s.NumericFields {
				s.Filters = append(s.Filters, FilterCapability{Field: field, Type: "number", Operators: []string{">", ">=", "<", "<="}, Modes: events, Description: "Exact numeric event comparison after capture, before delivery/reduction; missing values do not match. duration_ns/return_value/status require completion, file.fd requires paths, field.NAME must be selected. Not supported for snapshots or sampled aggregates. AND up to 16 predicates, decimal or hex thresholds up to 128 bytes; comparisons do not reduce kernel capture traffic."})
			}
		}
		if s.Name == "syscalls" || s.Name == "tracepoint" || s.Name == "disk" {
			for _, field := range []string{"name", "process_name", "name_group", "cgroup.path"} {
				s.Filters = append(s.Filters, filter(field, "string", "Exact value or one edge glob. Applied server-side after metadata enrichment; unavailable values do not match. Does not reduce eBPF ring traffic.", events))
			}
			s.Fields = append(s.Fields, FieldCapability{Path: "cgroup_path", Type: "string", QueryField: "cgroup.path", Optional: true, Description: "Best-effort per-thread unified cgroup membership from procfs at receipt; cached up to one second. Relative to server cgroup namespace; missing on v1, exit or invisible tasks. Not kernel-time identity or container-volume attribution."})
			if s.Name != "syscalls" {
				s.Fields = append(s.Fields, FieldCapability{Path: "pid", Type: "integer"}, FieldCapability{Path: "tid", Type: "integer"})
			}
			s.Fields = append(s.Fields, FieldCapability{Path: "name", Type: "string", Description: "Current task comm captured in kernel (up to 15 bytes); may differ between threads. Block events identify the issuing task, not necessarily the original application."})
			s.Fields = append(s.Fields, FieldCapability{Path: "process_name", Type: "string", Optional: true, Description: "Best-effort full executable basename from procfs at receipt; cached up to one second, may lag exec/PID reuse; unavailable for kernel tasks."}, FieldCapability{Path: "name_group", Type: "string", Optional: true, Description: "Task comm except verified kernel kworker/* tasks normalize to kworker; original name remains unchanged."})
			s.Fields = append(s.Fields, outputFields(CollectionStats{}, "collection")...)
		}
		if s.Name == "syscalls" || s.Name == "tracepoint" {
			s.Filters = append(s.Filters, filter("stacks", "string", "Optional symbolized stacks. Requires root server and explicit root policy. user.stack/kernel.stack grouping requires the corresponding capture. Capture is best-effort.", events, "user", "kernel", "both"), filter("stack.depth", "integer", "Capture depth, 0–64; zero defaults to 32. Requires stacks selection.", events))
			for _, prefix := range []string{"user.stack", "kernel.stack"} {
				from := filter(prefix+".from", "string", "Discard leaf-side frames before the first matching function. Equality or in with 1–16 alternative patterns; first frame matching any pattern wins. Only edge stars are wildcards; interior stars such as os.(*File).Sync are literal. No match leaves frames unchanged. Requires symbolization.", []string{"aggregate"})
				from.Operators = []string{"=", "in"}
				s.Filters = append(s.Filters,
					filter(prefix+".offsets", "boolean", "Keep offsets in aggregation keys (default true); false merges offset-only differences. Raw addresses remain distinct when unresolved.", []string{"aggregate"}, "true", "false"),
					filter(prefix+".drop_bottom", "integer", "Remove this many root-side captured frames before other shaping, 0–64.", []string{"aggregate"}),
					filter(prefix+".drop_top", "integer", "Remove this many leaf-side captured frames after drop_bottom, 0–64.", []string{"aggregate"}),
					from,
					filter(prefix+".top", "integer", "Keep at most this many leaf-side frames after trimming, 0–64; zero keeps all.", []string{"aggregate"}),
					filter(prefix+".until", "string", "Keep leaf-side frames through the first matching function, inclusive. Only edge stars are wildcards; interior stars are literal. No match leaves frames unchanged. Case-sensitive; requires symbolization.", []string{"aggregate"}))
			}
			s.GroupByFields = append(s.GroupByFields, "user.stack", "kernel.stack")
			s.Fields = append(s.Fields, outputFields(CapturedStack{}, "user_stack")...)
			s.Fields = append(s.Fields, outputFields(CapturedStack{}, "kernel_stack")...)
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
			if f.Path == "cgroup_path" {
				alias = "cgroup.path"
			}
			if s.Name == "disk" && strings.HasPrefix(alias, "io_cgroup_") {
				alias = "io.cgroup." + strings.TrimPrefix(alias, "io_cgroup_")
			}
			if s.Name == "syscalls" && strings.HasPrefix(f.Path, "file.") {
				alias = f.Path
			}
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
			case f.Path == "disk.io_cgroup_id":
				f.Description = "Kernel-time first-bio blkcg kernfs ID captured at issue and retained through completion. Requires supported BTF/CONFIG_BLK_CGROUP. No task-ownership fallback; synthetic flushes may have no bio."
			case f.Path == "disk.io_cgroup_path":
				f.Description = "Best-effort charged ID lookup in server's visible cgroup-v2 mount; directory cache refreshed up to once per second. Not the issuer's cgroup.path. Journal/metadata may legitimately remain root; no backing-volume inference."
			case f.Path == "disk.io_cgroup_error":
				f.Description = "Explicit unavailable association or invisible/deleted cgroup; known IDs remain available when paths cannot resolve."
			case f.Path == "disk.duration_ns":
				f.Unit = "nanoseconds"
				f.Description = "Completion only; latest issue to final completion, excluding pre-issue queueing."
			case f.Path == "disk.status":
				f.Description = "Completion only; last nonzero blk_status_t across partial completions, or zero on success. Kernel block status, not errno."
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
		if slices.Contains(s.Modes, "aggregate") {
			s.Filters = append(s.Filters,
				filter("result.format", "string", "One row per group with values aligned to columns; avoids repeating long group keys per metric. CLI default remains legacy; MCP JSON aggregates without jq default to rows.", []string{"aggregate"}, "rows"),
				filter("result.nonzero", "boolean", "Omit rows only when all metric values are numeric zero; nulls remain. Implies row format.", []string{"aggregate"}, "true", "false"),
				filter("result.limit", "integer", "Top N groups (0 unlimited, maximum 4096), descending by sort_metric after nonzero filtering. Selection affects output, not collection or group caps. Implies row format.", []string{"aggregate"}),
				filter("result.sort_metric", "integer", "Zero-based metric index for descending sorting (default first); exact numeric ordering, nulls last. All DSL result options select row format.", []string{"aggregate"}))
		}
	}
	return Capabilities{
		Version: 1, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Syntax: "SOURCE [where FIELD = VALUE [and ...]] [FUNCTION [, FUNCTION ...] over DURATION [every INTERVAL] [by FIELD, ...]]; alternatively one or more SELECTOR [where PREDICATES] { [let ALIAS = PROJECTION; ...] @TABLE[FIELD or ALIAS: FIELD/PROJECTION, ...] = {METRIC: FUNCTION(...), ...} } blocks followed by after DURATION { emit @TABLE [order by METRIC asc|desc] [limit N]; ... }; periodic: every INTERVAL { emit @TABLE; clear @TABLE; ... } after DURATION { stop }; count() | FUNCTION(FIELD) | percentile(FIELD, PERCENT) in actions; syscall in (N, :NAME, ...) and tracepoint fields in (NAME, ...)",
		Notes: []string{
			"Modes: events uses monitor/monitor-register; snapshot and aggregate use query. process without an aggregate is a snapshot in query and events in monitor.",
			"Platform support and authorization are reported separately. Runtime dependencies are not probed; queries can still fail due to kernel permissions, unsupported formats, missing tools or hardware.",
			"With a configured CA, authentication requires a valid CA-signed certificate with the configured principal. Without a CA, commands trust unrestricted plain keys from the requested account's OpenSSH authorized_keys; an omitted user targets the server account. Switching accounts requires a Unix root server. Queries, capabilities and monitors additionally accept keys from query-authorized-keys, which never authorizes commands. Query-only keys receive the server account's source access, including privileged sources on a root server; registered monitors retain per-key ownership. Key files are reloaded for each request; a server-account file override never applies to other accounts. Certificate root policy authorization and root account command keys also permit arbitrary root commands, unlike query-only keys. CA loading/validation failures never fall back to plain keys; query-authorized-keys cannot be combined with a CA.",
			"Filters use AND only; no OR, regex or interior globs. Both syntaxes accept =/==, in and numeric event comparisons >, >=, <, <=. Comparisons are signed, server-validated predicates on available numeric event fields, applied after capture before delivery/reduction (including periodic buckets and registered monitors). Missing values do not match. Thresholds are exact decimal integers/fractions or hexadecimal integers, up to 128 bytes; at most 16 comparisons. Snapshot and sampled aggregate comparisons are not supported. Source/field keywords in the original DSL are case-insensitive except kernel field names and name values. Quote values containing spaces.",
			"Aggregation collects a fresh half-open server-ingestion window [start,end), not registered-monitor history. Up to 8 functions share a single source subscription/sampler, window, interval, filters and grouping; no cross-source joins. Legacy multi results appear in aggregation.metrics in request order, each with function/field/percentile and counts or values; single-function result shape is unchanged. API aggregation.metrics replaces top-level function/field/percentile. All metrics share the 65536 retained-value budget; the 4096-group limit is per metric except periodic reports, which share 4096 retained metric groups across all buckets. Missing sampled metrics are skipped independently. Capture is best-effort; cancellation stops collection and source failures return errors.",
			"Selector/action syntax is case-sensitive and supports up to 8 selector/action blocks, one named table per block, not arbitrary scripting. Selectors: SOURCE, syscalls:entry/completion, disk:entry/completion, process:start/exit, tracepoint:CATEGORY:NAME. Tracepoints infer field.NAME references from predicates, locals, groups and metrics; explicit fields in (...) adds to the selection, maximum 16. No payload fields are needed for count/identity/stack-only actions. The original DSL still requires an explicit field list. Locals alias fields, stack.user/kernel(offsets: false, from: [\"literal\", glob(\"prefix*\")], until: \"literal\", top: N, drop_top: N, drop_bottom: N), or path.prefix(file.path, DEPTH). Actions infer stack/path capture. Groups support inline ALIAS: FIELD/PROJECTION, with unique output identifiers. Named metrics and group aliases appear in compact columns/rows; a lone function is named value. order by METRIC asc/desc supports limits in either direction, with nulls last and deterministic ties; default remains descending. API ascending=true selects low-to-high compact output. after emits a one-shot aggregation. every/clear plus after/stop creates finite non-overlapping event buckets (interval >=100ms, <=64 buckets, total <=1h), returned together in snapshot.windows at completion, not streamed live. The last bucket can be shorter and contains subscription-wide collection counters, not per-bucket loss. API report_every differs from snapshot sampling every. Periodic output is capped at 7 MiB. Both syntaxes use the same signing and authorization; monitor and registered monitors reject aggregates.",
			"Multi-selector scripts place all selector/action blocks before shared after/every reporting blocks. Every table must have a unique name and be emitted once; periodic reports require clear for each table. Locals, filters, capture, sorting and limits are selector-scoped. Independent subscriptions/samplers run concurrently on shared start/end and bucket boundaries, not atomic kernel attachment; repeated sources are allowed but not shared-table accumulation or cross-source joins. One-shot scripts may mix event and sampled snapshot sources; periodic scripts require event sources only. All selections are validated/authorized before collection, and any source error cancels its peers and fails the whole script. Results use snapshot.tables in selector order, each with source and aggregation or windows; jq uses .tables[].aggregation.rows[].values.NAME or .tables[].windows[].rows[].values.NAME. Existing single-selector output is unchanged. Collection budgets apply per selector; total script output <=7 MiB and query text <=4096 bytes. API: source=script, mode=aggregate, aggregation contains only shared window/report_every; probes contains 1–8 non-nested named aggregate requests with matching timing. The complete request is signed, syscall names resolve on the server, and both client/server need updating.",
			"Missing grouping fields use a JSON null bucket, for events and snapshots alike. Missing optional metric values are skipped independently, never fabricated as zero. Compact output uses aggregation.columns (metric descriptors) and rows [{group, values}], with total_groups before output filtering/limiting and omitted_zero_groups. Named tables (selector/action syntax) serialize values as an object keyed by metric name, e.g. {ops:724,p99:3800000}; use .aggregation.rows[].values.ops or .windows[].rows[].values.ops with jq. A lone function uses the name value. Groups remain a separate object to avoid name collisions. Original-DSL compact queries retain column-aligned arrays; unavailable group metrics are null in both formats. Named-table pipelines must switch from .values[INDEX] to .values.NAME; both client/server need updating. Go AggregateRow.Values stays column-aligned and decoding accepts either format. API controls: compact, nonzero, limit, sort_metric, ascending. Legacy output is retained by default except MCP JSON aggregates without jq; MCP format=legacy opts out. Compact controls cannot be combined with folded output.",
			"Disk rwbs is the kernel request flag string: optional leading F=preflush, operation R/W/D/F/N (DE=secure erase), then F=FUA, A=readahead, S=sync and M=metadata. Supported BTF kernels reconstruct both phases from issue cmd_flags; request_flags retains raw flags. Entry falls back to tracefs C-string decoding without BTF; stops at the first null. device_name is a best-effort sysfs name. collection block_issues/block_completions count callbacks before filtering; block_reissues counts issues replacing a pending pointer. block_partial_completions and block_final_completions separate matched callbacks, with one event per final completion. unmatched_exits counts callbacks without a pending pointer, not unique requests; attachment boundaries, repeated callbacks and pairing failures need separate investigation.",
			"Sources with sampling metadata support sampled snapshot aggregates. every defaults to 1s for snapshot-only sources; process requires explicit every to select snapshots instead of lifecycle events. Sampling fields are record-relative paths, not event field aliases.",
			"Samples are collected immediately and on the interval grid before the window ends; slow reads skip ticks without overlap. count counts observed records. avg is an arithmetic sample mean, not time-weighted; sum of a gauge is a sum of observations, not an integral. Missing optional metrics are skipped, not zero.",
			"Raw counters cannot be summed/averaged/minimized/maximized/percentiled. Use FIELD_per_second for rates, or CPU utilization_percent. Derived values require consecutive observations, so the first observation is only a baseline. Resets, disappearing/reappearing entities, and missing fields start a new baseline; no zero is fabricated. A derived query needs a window longer than its interval.",
			"Cgroup io.stat total rates additionally require the same device set and monotonic per-device counters; device changes or any device reset skip that metric's interval and restart its baseline. io.read_bytes/write_bytes/discard_bytes are bytes; io.read_ios/write_ios/discard_ios are operations. Empty available io.stat measures zero; absent files/keys remain unavailable.",
			"Process snapshots include best-effort CPU seconds, RSS/virtual memory bytes, user, state, threads and command line. Unavailable values are omitted. Sampled process cpu_percent is 100 × delta cpu_seconds / elapsed seconds, excluding children: 100% is one busy core and multithreaded processes may exceed 100%. PID/start time identifies observations so PID reuse restarts the baseline.",
			"Group/numeric field names are DSL aliases: src.ip/dst.ip map to packet.source_ip/destination_ip; src.port/dst.port map to packet.source_port/destination_port; name/action map to process.name/action; field.NAME maps to tracepoint.fields.NAME.",
			"Tracepoint common_pid is obtained from the eBPF current-task helper. Other hidden trace header fields, including common_type, common_flags and common_preempt_count, are unavailable and rejected.",
			"Tracepoint common_pid is the task/thread executing the tracepoint, not necessarily the application that requested the work. Block I/O can be issued by kernel workers after asynchronous writeback or merging; grouping block:block_rq_issue by field.common_pid is not exact per-application disk accounting.",
			"Event time is UTC receipt time. tai64n is the resumable registered-monitor cursor. Registered monitors survive disconnects, not server restarts; bounded storage can overwrite old events. Reads reset the idle TTL.",
			"Syscalls phase=completion pairs entries/exits by thread in a bounded map. duration_ns and return_value are completion-only aggregate fields. Stacks/name are retained from entry. Calls without observed completion are excluded; sum(duration_ns) is accumulated task time and can exceed wall time. Syscall numbers are architecture-specific.",
			"Task-context eBPF events (syscalls, disk, tracepoint) expose pid, tid and name without stacks. Packet capture does not infer a process owner. collection counters are cumulative per subscription, never additive across events; aggregate results include a final collection snapshot. kind=collection_stats records are diagnostics, not data events. Stack capture failures include collisions; stacks use 16384 stable slots, never ID reuse. Counters describe collection before user-space tracepoint filtering; ring drops are not per-group estimates.",
			"Stack shaping is a signed server-side aggregation projection, independent for user/kernel stacks. Order is drop_bottom, drop_top, from, until, top, then optional offset removal. from keeps the matched frame and callers; until keeps leaf frames through the match. It never changes raw captured frames or erases capture-error markers. Unresolved file-backed user frames retain module path and file_offset; keys render module@file+0xOFFSET even with offsets=false. Aggregation stack keys are leaf-first; frame separators/control characters and percent are percent-escaped. CLI --format folded reverses them to root-first flame graph paths, preserving other grouping dimensions as prefix frames; --folded-stack chooses user.stack/kernel.stack and --folded-metric chooses a zero-based metric. JSON is the default; folded output and jq pipelines cannot be combined. Folded weights must be nonnegative numeric values; nonzero collection counters go to stderr.",
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
		Limits:      CapabilityLimits{QueryBytes: 4096, MaxWindow: "1h", GroupByFields: 4, Groups: maxAggregateGroups, RetainedAggregateValues: maxAggregateValues, AggregateMetrics: maxAggregateMetrics, TracepointFields: 16, SyscallFilters: 256, PacketCaptureBytes: 2048, DefaultMonitorTTL: DefaultMonitorTTL.String(), RegisteredMonitors: maxRegisteredMonitors, MonitorRingEvents: monitorRingSize, MonitorEventBytes: maxMonitorEventSize},
		EventFields: []FieldCapability{{Path: "time", Type: "timestamp", Description: "UTC receipt time"}, {Path: "tai64n", Type: "string", Description: "TAI64N timestamp/cursor for resuming monitor reads"}},
	}
}
