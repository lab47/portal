//go:build linux

package portal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

const schedWakeupFormat = `name: sched_wakeup
format:
	field:unsigned short common_type; offset:0; size:2; signed:0;
	field:unsigned char common_flags; offset:2; size:1; signed:0;
	field:char comm[16]; offset:8; size:16; signed:0;
	field:pid_t pid; offset:24; size:4; signed:1;
	field:int prio; offset:28; size:4; signed:1;
	field:int target_cpu; offset:32; size:4; signed:1;
	field:unsigned long long timestamp; offset:40; size:8; signed:0;
	field:__data_loc char[] filename; offset:48; size:4; signed:1;
	field:void *ptr; offset:56; size:8; signed:0;
`

func TestGenericTracepointFormatAndRecord(t *testing.T) {
	spec := TracepointFilter{Event: "sched:sched_wakeup", Fields: []string{"target_cpu", "pid", "timestamp", "prio"}, Equals: map[string]string{"target_cpu": "3", "prio": "-2"}}
	fields, err := parseTracepointFormat(schedWakeupFormat, spec.Fields)
	if err != nil {
		t.Fatal(err)
	}
	if fields[0].offset != 32 || fields[1].offset != 24 || fields[2].offset != 40 || !fields[3].signed {
		t.Fatalf("fields not ordered by request: %+v", fields)
	}
	insns := tracepointInstructions(fields, 42)
	if err := insns.Marshal(&bytes.Buffer{}, binary.LittleEndian); err != nil {
		t.Fatalf("invalid eBPF instructions: %v", err)
	}
	if insns[1].Offset != 32 || insns[3].Offset != 24 || insns[5].Offset != 40 || insns[7].Offset != 28 || insns[1].OpCode != asm.LoadMem(asm.R7, asm.R6, 32, asm.Word).OpCode {
		t.Fatalf("wrong eBPF field loads: %v", insns)
	}
	raw := make([]byte, 32)
	binary.NativeEndian.PutUint64(raw[0:8], 3)
	binary.NativeEndian.PutUint64(raw[8:16], 4312)
	binary.NativeEndian.PutUint64(raw[16:24], ^uint64(0))
	binary.NativeEndian.PutUint64(raw[24:32], 0xfffffffe)
	event, err := decodeTracepointRecord(raw, spec, fields)
	if err != nil || event.Tracepoint == nil || event.Tracepoint.Fields["prio"] != "-2" || event.Tracepoint.Fields["timestamp"] != "18446744073709551615" || event.Time.IsZero() {
		t.Fatalf("decoded %+v: %v", event, err)
	}
	request := MonitorRequest{Source: "tracepoint", Tracepoint: &spec}
	if err := request.validate(); err != nil || !request.matches(event) || (MonitorRequest{Source: "syscalls"}).matches(event) {
		t.Fatalf("invalid match or request: %v", err)
	}
	encoded, err := json.Marshal(event)
	var decoded Event
	if err == nil {
		err = json.Unmarshal(encoded, &decoded)
	}
	if err != nil || decoded.Tracepoint.Fields["timestamp"] != "18446744073709551615" || strings.Contains(string(encoded), `"syscall"`) {
		t.Fatalf("lost precision or emitted unrelated field: %s: %v", encoded, err)
	}
	for _, changed := range []Event{
		{Tracepoint: &TracepointEvent{Event: "sched:sched_switch", Fields: event.Tracepoint.Fields}},
		{Tracepoint: &TracepointEvent{Event: spec.Event, Fields: map[string]json.Number{"target_cpu": "4", "prio": "-2"}}},
		{Tracepoint: &TracepointEvent{Event: spec.Event, Fields: map[string]json.Number{"target_cpu": "3"}}},
	} {
		if request.matches(changed) {
			t.Fatalf("accepted mismatched tracepoint event: %+v", changed)
		}
	}
	if _, err := decodeTracepointRecord(raw[:31], spec, fields); err == nil {
		t.Fatal("accepted truncated ringbuf record")
	}
}

func TestGenericTracepointRejectsUnsupportedFields(t *testing.T) {
	for _, name := range []string{"comm", "filename", "ptr", "missing"} {
		if _, err := parseTracepointFormat(schedWakeupFormat, []string{name}); err == nil {
			t.Fatalf("accepted unsupported or missing field %s", name)
		}
	}
	for _, bad := range []string{
		strings.Replace(schedWakeupFormat, "offset:24;", "offset:4094;", 1),
		strings.Replace(schedWakeupFormat, "size:4; signed:1;\n\tfield:int prio", "size:3; signed:1;\n\tfield:int prio", 1),
		strings.Replace(schedWakeupFormat, "field:pid_t pid; offset:24", "field:pid_t pid; offset:24; size:4; signed:1;\n\tfield:pid_t pid; offset:24", 1),
	} {
		if _, err := parseTracepointFormat(bad, []string{"pid"}); err == nil {
			t.Fatalf("accepted invalid format: %s", bad)
		}
	}
}
