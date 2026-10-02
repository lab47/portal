//go:build linux

package portal

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

const blockIssueFormat = `name: block_rq_issue
format:
	field:unsigned short common_type; offset:0; size:2; signed:0;
	field:dev_t dev; offset:8; size:4; signed:0;
	field:sector_t sector; offset:16; size:8; signed:0;
	field:unsigned int nr_sector; offset:24; size:4; signed:0;
	field:char rwbs[8]; offset:28; size:8; signed:0;
`

func TestDiskTracepointFormatAndRecord(t *testing.T) {
	fields, err := parseDiskFormat(blockIssueFormat)
	if err != nil {
		t.Fatal(err)
	}
	if fields["rwbs"].offset != 28 || fields["sector"].offset != 16 {
		t.Fatalf("wrong tracepoint offsets: %+v", fields)
	}
	insns := diskInstructions(fields, 42, &DiskFilter{Device: 17, Operation: "write"})
	if err := insns.Marshal(&bytes.Buffer{}, binary.LittleEndian); err != nil {
		t.Fatalf("invalid eBPF instructions: %v", err)
	}
	if len(insns) < 10 || insns[1].OpCode != asm.LoadMem(asm.R7, asm.R6, 8, asm.Word).OpCode || insns[1].Offset != 8 {
		t.Fatal("device offset not loaded from format")
	}
	raw := make([]byte, taskIdentitySize+24)
	binary.NativeEndian.PutUint64(raw[:8], uint64(123)<<32|456)
	copy(raw[8:24], "disk-worker")
	payload := raw[taskIdentitySize:]
	binary.NativeEndian.PutUint32(payload[:4], 17)
	binary.NativeEndian.PutUint32(payload[4:8], 8)
	binary.NativeEndian.PutUint64(payload[8:16], 12345)
	payload[16] = 'W'
	event, err := decodeDiskRecord(raw)
	if err != nil || event.PID != 123 || event.TID != 456 || event.Name != "disk-worker" || event.Disk.Device != 17 || event.Disk.Sector != 12345 || event.Disk.Sectors != 8 || event.Disk.Operation != "write" || event.Time.IsZero() {
		t.Fatalf("decoded %+v, %v", event, err)
	}
	if !(&MonitorRequest{Source: "disk", Disk: &DiskFilter{Device: 17, Operation: "write"}}).matches(event) {
		t.Fatal("matching disk request rejected")
	}
	for _, request := range []MonitorRequest{
		{Source: "disk", Disk: &DiskFilter{Device: 18}},
		{Source: "disk", Disk: &DiskFilter{Operation: "read"}},
		{Source: "syscalls"},
	} {
		if request.matches(event) {
			t.Fatalf("unrelated filter matched disk event: %+v", request)
		}
	}
	for _, request := range []MonitorRequest{
		{Source: "disk", PID: 1},
		{Source: "disk", Packet: &PacketFilter{}},
		{Source: "disk", Disk: &DiskFilter{Operation: "unknown"}},
	} {
		if err := request.validate(); err == nil {
			t.Fatalf("invalid disk request accepted: %+v", request)
		}
	}
	if _, err := decodeDiskRecord(raw[:23]); err == nil {
		t.Fatal("truncated record accepted")
	}
	for _, bad := range []string{
		strings.Replace(blockIssueFormat, "nr_sector;", "wrong;", 1),
		strings.Replace(blockIssueFormat, "rwbs[8]", "rwbs[0]", 1),
		strings.Replace(blockIssueFormat, "sector; offset:16; size:8", "sector; offset:16; size:4", 1),
	} {
		if _, err := parseDiskFormat(bad); err == nil {
			t.Fatalf("invalid format accepted: %s", bad)
		}
	}
}
