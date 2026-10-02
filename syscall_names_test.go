package portal

import (
	"context"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSymbolicSyscallQueries(t *testing.T) {
	for _, tc := range []struct {
		query string
		ids   []int
		names []string
	}{
		{"syscalls where syscall = :fsync", nil, []string{"fsync"}},
		{"syscalls where syscall in (:fsync, 0, :fdatasync)", []int{0}, []string{"fsync", "fdatasync"}},
		{"syscalls where phase = completion and syscall in (:fsync,:fdatasync) sum(duration_ns) over 30s by pid", nil, []string{"fsync", "fdatasync"}},
	} {
		r, err := ParseMonitorQuery(tc.query)
		if err != nil || !reflect.DeepEqual(r.Syscalls, tc.ids) || !reflect.DeepEqual(r.SyscallNames, tc.names) {
			t.Fatalf("%s: %+v, %v", tc.query, r, err)
		}
	}
	for _, text := range []string{":", ":FSYNC", ":fsync*", "::fsync", "#fsync", "fsync", ":123", ":fsync/path"} {
		if _, err := ParseMonitorQuery("syscalls where syscall = " + text); err == nil {
			t.Fatalf("accepted malformed syscall %q", text)
		}
	}
	for _, r := range []MonitorRequest{
		{Source: "process", SyscallNames: []string{"fsync"}},
		{Source: "syscalls", SyscallNames: []string{":fsync"}},
		{Source: "syscalls", Syscalls: make([]int, 256), SyscallNames: []string{"fsync"}},
	} {
		if err := r.validate(); err == nil {
			t.Fatalf("accepted invalid request: %+v", r)
		}
	}
}

func TestResolveSyscallNamesServerArchitecture(t *testing.T) {
	request := MonitorRequest{Source: "syscalls", Syscalls: []int{0}, SyscallNames: []string{"fsync", "fdatasync"}}
	for _, tc := range []struct {
		arch string
		ids  []int
	}{
		{"amd64", []int{0, 74, 75}},
		{"arm64", []int{0, 82, 83}},
		{"386", []int{0, 118, 148}},
		{"arm", []int{0, 118, 148}},
	} {
		got, err := resolveSyscallNames(request, tc.arch)
		if err != nil || !reflect.DeepEqual(got.Syscalls, tc.ids) || len(got.SyscallNames) != 0 {
			t.Fatalf("%s: %+v, %v", tc.arch, got, err)
		}
		if !got.matches(Event{Syscall: tc.ids[1]}) || got.matches(Event{Syscall: 999}) {
			t.Fatalf("resolved selection failed: %+v", got)
		}
	}
	if len(request.Syscalls) != 1 || len(request.SyscallNames) != 2 {
		t.Fatal("resolution mutated the signed request")
	}
	for _, tc := range []struct{ arch, name string }{
		{"amd64", "not_a_syscall"}, {"arm64", "open"}, {"riscv64", "fsync"},
	} {
		_, err := resolveSyscallNames(MonitorRequest{Source: "syscalls", SyscallNames: []string{tc.name}}, tc.arch)
		if err == nil || !strings.Contains(err.Error(), tc.arch) {
			t.Fatalf("unsupported name/arch not rejected: %+v, %v", tc, err)
		}
	}
	// Numeric-only queries remain available even without a name table.
	if _, err := resolveSyscallNames(MonitorRequest{Source: "syscalls", Syscalls: []int{1}}, "riscv64"); err != nil {
		t.Fatal(err)
	}
}

func TestRegisteredMonitorResolvesSyscallNames(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("asserts x86-64 syscall IDs")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := make(chan MonitorRequest, 1)
	store := newMonitorStore(ctx, func(ctx context.Context, r MonitorRequest, emit func(Event) error) error {
		seen <- r
		if err := emit(Event{Syscall: 74}); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	})
	id, err := store.create("owner", MonitorRequest{Source: "syscalls", Syscalls: []int{0}, SyscallNames: []string{"fsync"}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.delete(id, "owner")
	r := <-seen
	if !reflect.DeepEqual(r.Syscalls, []int{0, 74}) || len(r.SyscallNames) != 0 {
		t.Fatalf("collector received unresolved request: %+v", r)
	}
	m, err := store.get(id, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if !m.request.matches(Event{Syscall: 74}) || m.request.matches(Event{Syscall: 75}) {
		t.Fatal("registered monitor retained unresolved userspace filter")
	}
	if _, err := store.create("owner", MonitorRequest{Source: "syscalls", SyscallNames: []string{"not_a_syscall"}}); err == nil {
		t.Fatal("unknown name registered a monitor")
	}
}
