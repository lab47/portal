package portal

import (
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestIOQueryFields(t *testing.T) {
	for _, q := range []string{
		"syscalls where paths = true and phase = completion and syscall in (:fsync,:fdatasync) count, sum(duration_ns) over 30s by pid, file.path",
		"disk where phase = completion count, avg(duration_ns), percentile(duration_ns,95) over 30s by device, pid, name",
	} {
		if _, err := ParseMonitorQuery(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, q := range []string{
		"syscalls count over 1s by file.path", "disk avg(duration_ns) over 1s", "syscalls where paths = maybe", "process where phase = completion", "disk where phase = unknown",
	} {
		if _, err := ParseMonitorQuery(q); err == nil {
			t.Fatalf("accepted %s", q)
		}
	}
	if err := (MonitorRequest{Source: "disk", Paths: true}).validate(); err == nil {
		t.Fatal("disk paths accepted")
	}
	d := uint64(321)
	fields := eventGroupFields(Event{Disk: &DiskEvent{Device: 11, DurationNS: &d}, PID: 12}, nil)
	if fields["duration_ns"] != d || fields["pid"] != uint32(12) {
		t.Fatalf("disk fields: %+v", fields)
	}
	fields = eventGroupFields(Event{File: &SyscallFile{FD: 7, Path: "/data/test"}}, nil)
	if fields["file.path"] != "/data/test" || fields["file.fd"] != int32(7) {
		t.Fatalf("file fields: %+v", fields)
	}
	for _, s := range describeCapabilities(policy{}, &ssh.Certificate{}).Sources {
		if s.Name == "disk" && !slices.Contains(s.NumericFields, "duration_ns") {
			t.Fatal("disk latency undiscoverable")
		}
		if s.Name == "syscalls" && !slices.Contains(s.GroupByFields, "file.path") {
			t.Fatal("paths undiscoverable")
		}
	}
}
