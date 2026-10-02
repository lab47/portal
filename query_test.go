package portal

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseMonitorQuery(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  MonitorRequest
	}{
		{"packets", MonitorRequest{Source: "packets"}},
		{"process", MonitorRequest{Source: "process"}},
		{"cpu", MonitorRequest{Source: "cpu", Mode: "snapshot"}},
		{"memory", MonitorRequest{Source: "memory", Mode: "snapshot"}},
		{"network where name = eth*", MonitorRequest{Source: "network", Mode: "snapshot", Name: "eth*"}},
		{"kernel", MonitorRequest{Source: "kernel", Mode: "snapshot"}},
		{"sensors where name = '*temp1'", MonitorRequest{Source: "sensors", Mode: "snapshot", Name: "*temp1"}},
		{"containers where name = web*", MonitorRequest{Source: "containers", Mode: "snapshot", Name: "web*"}},
		{"gpu where name = '*A100'", MonitorRequest{Source: "gpu", Mode: "snapshot", Name: "*A100"}},
		{"disk where operation = WRITE and device = 0x1234", MonitorRequest{Source: "disk", Disk: &DiskFilter{Operation: "write", Device: 0x1234}}},
		{"tracepoint where event = sched:sched_wakeup and fields in (pid, target_cpu) and field.target_cpu = 0x2", MonitorRequest{Source: "tracepoint", Tracepoint: &TracepointFilter{Event: "sched:sched_wakeup", Fields: []string{"pid", "target_cpu"}, Equals: map[string]string{"target_cpu": "0x2"}}}},
		{"tracepoint where event = custom:sample and fields in (CamelCase) and FIELD.CamelCase = 08", MonitorRequest{Source: "tracepoint", Tracepoint: &TracepointFilter{Event: "custom:sample", Fields: []string{"CamelCase"}, Equals: map[string]string{"CamelCase": "08"}}}},
		{"process where name = worker*", MonitorRequest{Source: "process", Process: &ProcessFilter{Name: "worker*"}}},
		{"process where name = '*Helper'", MonitorRequest{Source: "process", Process: &ProcessFilter{Name: "*Helper"}}},
		{"process where pid = 123 and name = worker and action = START", MonitorRequest{Source: "process", PID: 123, Process: &ProcessFilter{Name: "worker", Action: "start"}}},
		{`process where name = "Google Chrome Helper" and action = exit`, MonitorRequest{Source: "process", Process: &ProcessFilter{Name: "Google Chrome Helper", Action: "exit"}}},
		{`process where name = 'worker\'s agent'`, MonitorRequest{Source: "process", Process: &ProcessFilter{Name: "worker's agent"}}},
		{"syscalls where pid=42 and syscall in(0, 1,9)", MonitorRequest{Source: "syscalls", PID: 42, Syscalls: []int{0, 1, 9}}},
		{"syscalls where syscall = 0", MonitorRequest{Source: "syscalls", Syscalls: []int{0}}},
		{"syscalls where syscall = 2 count over 30s by pid", MonitorRequest{Source: "syscalls", Mode: "aggregate", Syscalls: []int{2}, Aggregation: &AggregationRequest{Window: 30 * time.Second, GroupBy: []string{"pid"}}}},
		{"PROCESS COUNT OVER 1m BY NAME, ACTION  ", MonitorRequest{Source: "process", Mode: "aggregate", Aggregation: &AggregationRequest{Window: time.Minute, GroupBy: []string{"name", "action"}}}},
		{"disk count over 1h", MonitorRequest{Source: "disk", Mode: "aggregate", Aggregation: &AggregationRequest{Window: time.Hour}}},
		{"packets where dst.port = 80 and protocol = tcp SUM ( LENGTH ) over 30s by dst.port", MonitorRequest{Source: "packets", Mode: "aggregate", Packet: &PacketFilter{Protocol: "tcp", DestinationPort: 80}, Aggregation: &AggregationRequest{Window: 30 * time.Second, Function: "sum", Field: "length", GroupBy: []string{"dst.port"}}}},
		{"disk avg(sectors) over 1m", MonitorRequest{Source: "disk", Mode: "aggregate", Aggregation: &AggregationRequest{Window: time.Minute, Function: "avg", Field: "sectors"}}},
		{"syscalls min(pid) over 1s", MonitorRequest{Source: "syscalls", Mode: "aggregate", Aggregation: &AggregationRequest{Window: time.Second, Function: "min", Field: "pid"}}},
		{"syscalls max(tid) over 1s", MonitorRequest{Source: "syscalls", Mode: "aggregate", Aggregation: &AggregationRequest{Window: time.Second, Function: "max", Field: "tid"}}},
		{"process count_distinct(name) over 1s", MonitorRequest{Source: "process", Mode: "aggregate", Aggregation: &AggregationRequest{Window: time.Second, Function: "count_distinct", Field: "name"}}},
		{"disk percentile(sectors, 99.9) over 1s by device", MonitorRequest{Source: "disk", Mode: "aggregate", Aggregation: &AggregationRequest{Window: time.Second, Function: "percentile", Field: "sectors", Percentile: 99.9, GroupBy: []string{"device"}}}},
		{"tracepoint where event = custom:sample and fields in (CamelCase) min(FIELD.CamelCase) over 1s", MonitorRequest{Source: "tracepoint", Mode: "aggregate", Tracepoint: &TracepointFilter{Event: "custom:sample", Fields: []string{"CamelCase"}}, Aggregation: &AggregationRequest{Window: time.Second, Function: "min", Field: "field.CamelCase"}}},
		{"tracepoint where event = custom:sample and fields in (CamelCase) count over 2s by FIELD.CamelCase", MonitorRequest{Source: "tracepoint", Mode: "aggregate", Tracepoint: &TracepointFilter{Event: "custom:sample", Fields: []string{"CamelCase"}}, Aggregation: &AggregationRequest{Window: 2 * time.Second, GroupBy: []string{"field.CamelCase"}}}},
		{"packets where protocol = tcp and direction = outgoing and dst.port = 80", MonitorRequest{Source: "packets", Packet: &PacketFilter{Protocol: "tcp", Direction: "outgoing", DestinationPort: 80}}},
		{"packets where src.ip = 2001:0db8::1 and dst.ip = 192.0.2.5 and protocol = UDP and src.port = 5353 and dst.port = 53", MonitorRequest{Source: "packets", Packet: &PacketFilter{Protocol: "udp", SourceIP: "2001:0db8::1", DestinationIP: "192.0.2.5", SourcePort: 5353, DestinationPort: 53}}},
	} {
		t.Run(tc.query, func(t *testing.T) {
			got, err := ParseMonitorQuery(tc.query)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseMonitorQuery(%q) = %+v, %v; want %+v", tc.query, got, err, tc.want)
			}
		})
	}
	request, err := ParseMonitorQuery("packets where protocol = tcp and direction = outgoing and dst.port = 80")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		event Event
		want  bool
	}{
		{Event{Packet: &PacketEvent{Protocol: "tcp", Direction: "outgoing", SourcePort: 443, DestinationPort: 80}}, true},
		{Event{Packet: &PacketEvent{Protocol: "tcp", Direction: "outgoing", SourcePort: 80, DestinationPort: 443}}, false},
		{Event{Packet: &PacketEvent{Protocol: "udp", Direction: "outgoing", DestinationPort: 80}}, false},
		{Event{Packet: &PacketEvent{Protocol: "tcp", Direction: "incoming", DestinationPort: 80}}, false},
	} {
		if got := request.matches(tc.event); got != tc.want {
			t.Fatalf("query matched %+v = %v, want %v", tc.event, got, tc.want)
		}
	}
}

func TestParseMonitorQueryRejectsAmbiguity(t *testing.T) {
	for _, query := range []string{
		"", "anything", "packets where", "packets protocol = tcp", "packets where protocol =", "packets where protocol == tcp",
		"packets where protocol = tcp and", "packets where protocol = tcp protocol = udp", "packets where protocol = tcp and protocol = udp",
		"packets where dst.port = 80", "packets where protocol = icmp", "packets where protocol = tcp and dst.port = 65536",
		"packets where protocol = tcp and dst.port = 0", "packets where pid = 42", "packets where protocol in (tcp,udp)",
		"syscalls where src.port = 80", "syscalls where pid = 0", "syscalls where pid = -1", "syscalls where syscall = 65536",
		"syscalls where syscall in ()", "syscalls where syscall in (0,)", "syscalls where syscall in (0 1)",
		"syscalls where syscall in (0,1", "syscalls where syscall in (0) and syscall = 2", "syscalls where syscall = -1",
		"process where action = restart", "process where pid = 0", "process where name = worker and syscall = 1",
		"process where name = *", "process where name = wor*ker", "process where name = *work*",
		"disk where pid = 2", "disk where device = 0", "disk where operation = trim", "disk where operation in (read,write)",
		"tracepoint", "tracepoint where event = sched:sched_wakeup", "tracepoint where fields in (pid)",
		"tracepoint where event = ../sched:sched_wakeup and fields in (pid)",
		"tracepoint where event = sched:sched_wakeup and fields in (pid, pid)",
		"tracepoint where event = sched:sched_wakeup and fields in (pid) and field.prio = 2",
		"tracepoint where event = sched:sched_wakeup and fields in (pid) and field.pid = nope",
		"tracepoint where event = sched:sched_wakeup and fields in (pid) and field.pid = 18446744073709551616",
		"tracepoint where event = sched:sched_wakeup and fields in (pid) and mode = snapshot",
		"cpu where pid = 1", "memory where name = ram", "kernel where load = 1", "network where name = e*th", "sensors where name = *",
		"containers where name = a*b", "gpu where index = 0",
		"syscalls count over 0s", "syscalls count over -1s", "syscalls count over 2h", "syscalls count over nope",
		"syscalls count over 999999999999999999999s", "syscalls count over 30s by", "syscalls count over 30s by pid,",
		"syscalls count over 30s by pid,pid", "syscalls count over 30s by nope", "syscalls count over 30s by pid tid",
		"syscalls count over 30s where syscall = 2", "syscalls sum over 30s", "capabilities count over 30s",
		"packets count over 30s by pid", "disk count over 30s by nope", "process count over 30s by syscall",
		"tracepoint where event = custom:sample and fields in (pid) count over 30s by field.unselected",
		"packets count over 30s by protocol,direction,src.ip,dst.ip,src.port",
		"process sum(name) over 1s", "packets avg(src.ip) over 1s", "disk min(operation) over 1s",
		"syscalls sum() over 1s", "syscalls count(pid) over 1s", "syscalls count_distinct() over 1s",
		"syscalls count_distinct(nope) over 1s", "syscalls max(nope) over 1s", "syscalls sum(pid,tid) over 1s",
		"syscalls percentile(pid) over 1s", "syscalls percentile(pid,NaN) over 1s", "syscalls percentile(pid,Inf) over 1s",
		"syscalls percentile(pid,-0.1) over 1s", "syscalls percentile(pid,100.1) over 1s", "syscalls percentile(pid,bad) over 1s",
		"syscalls percentile(pid,95,99) over 1s", "syscalls sum(pid) max(pid) over 1s",
		"tracepoint where event = custom:sample and fields in (pid) sum(field.other) over 1s",
		`process where name = ""`, `process where name = "broken`, `process where name = "okay"suffix`, `process where name = "bad\q"`,
		"packets where protocol = tcp or protocol = udp", strings.Repeat("a", 4097),
	} {
		t.Run(query, func(t *testing.T) {
			if got, err := ParseMonitorQuery(query); err == nil {
				t.Fatalf("invalid query accepted: %+v", got)
			}
		})
	}
}
