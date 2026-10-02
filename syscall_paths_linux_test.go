//go:build linux

package portal

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestResolveSyscallFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "target")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw := make([]byte, 8)
	binary.NativeEndian.PutUint32(raw[:4], uint32(f.Fd()))
	binary.NativeEndian.PutUint32(raw[4:], 1)
	e := Event{PID: uint32(os.Getpid()), TID: uint32(unix.Gettid()), Syscall: unix.SYS_FSYNC}
	resolveSyscallFile(raw, &e)
	if e.File == nil || e.File.Path != f.Name() || e.File.Error != "" {
		t.Fatalf("file: %+v", e.File)
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil || decoded.File == nil || decoded.File.Path != f.Name() {
		t.Fatalf("wire: %s, %v", data, err)
	}
	binary.NativeEndian.PutUint32(raw[:4], ^uint32(0))
	resolveSyscallFile(raw, &e)
	if e.File.FD != -1 || e.File.Error == "" || e.File.Path != "" {
		t.Fatalf("invalid FD: %+v", e.File)
	}
	binary.NativeEndian.PutUint32(raw[:4], 2147483647)
	resolveSyscallFile(raw, &e)
	if e.File.Error == "" || e.File.Path != "" {
		t.Fatalf("missing FD: %+v", e.File)
	}
	e.File = nil
	binary.NativeEndian.PutUint32(raw[4:], 0)
	resolveSyscallFile(raw, &e)
	if e.File != nil {
		t.Fatal("non-file syscall acquired a file")
	}
}

func TestSyscallPathsLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root tracepoints")
	}
	for _, phase := range []string{"entry", "completion"} {
		t.Run(phase, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "fsync-target")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.Write([]byte("path probe")); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			got := make(chan Event, 128)
			done := make(chan error, 1)
			go func() {
				done <- syscallEvents(ctx, MonitorRequest{Source: "syscalls", PID: uint32(os.Getpid()), Phase: phase, Paths: true, Syscalls: []int{unix.SYS_FSYNC, unix.SYS_GETPID}, Stacks: &StackCapture{Kernel: true}}, func(e Event) error {
					select {
					case got <- e:
					default:
					}
					return nil
				})
			}()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			tid := uint32(unix.Gettid())
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			found := false
			for !found {
				select {
				case <-ticker.C:
					unix.Getpid()
					if err := unix.Fsync(int(f.Fd())); err != nil {
						t.Fatal(err)
					}
				case e := <-got:
					if e.Syscall == unix.SYS_FSYNC && e.TID == tid {
						if e.File == nil || e.File.Path != f.Name() || e.File.FD != int32(f.Fd()) || e.File.Error != "" || e.KernelStack == nil {
							t.Fatalf("bad event: %+v file=%+v", e, e.File)
						}
						if phase == "completion" && (e.DurationNS == nil || e.ReturnValue == nil || *e.ReturnValue != 0) {
							t.Fatalf("bad completion: %+v", e)
						}
						found = true
					}
					if e.Syscall == unix.SYS_GETPID && e.File != nil {
						t.Fatal("getpid has file")
					}
				case err := <-done:
					t.Fatalf("collector stopped: %v", err)
				case <-deadline.C:
					t.Fatal("no fsync event")
				}
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
