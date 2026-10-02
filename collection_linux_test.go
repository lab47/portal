//go:build linux

package portal

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestCollectionKernelLossCounters(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for forced BPF capture loss")
	}
	for _, collision := range []bool{false, true} {
		t.Run(map[bool]string{false: "ring_full", true: "stack_collision"}[collision], func(t *testing.T) {
			collection, err := newCollectionState()
			if err != nil {
				t.Fatal(err)
			}
			defer collection.close()
			insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.FnGetCurrentPidTgid.Call(), asm.RSh.Imm(asm.R0, 32), asm.JNE.Imm32(asm.R0, int32(os.Getpid()), "exit"), asm.LoadMem(asm.R0, asm.R6, 8, asm.DWord), asm.JNE.Imm(asm.R0, int32(unix.SYS_GETPID), "exit")}
			if collision {
				m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.StackTrace, KeySize: 4, ValueSize: 64, MaxEntries: 1})
				if err != nil {
					t.Fatal(err)
				}
				defer m.Close()
				s := &stackCaptureState{spec: StackCapture{User: true, Kernel: true, Depth: 8}, stackMap: m, collection: collection}
				insns = appendStackCapture(insns, asm.R6, -24, s)
			} else {
				m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 4096})
				if err != nil {
					t.Fatal(err)
				}
				defer m.Close()
				insns = append(insns, asm.Mov.Imm(asm.R0, 0), asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord), asm.LoadMapPtr(asm.R1, m.FD()), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.Mov.Imm(asm.R3, 8), asm.Mov.Imm(asm.R4, 0), asm.FnRingbufOutput.Call())
				insns = appendRingLoss(insns, collection)
			}
			insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
			program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.RawTracepoint, License: "GPL", Instructions: insns})
			if err != nil {
				t.Fatal(err)
			}
			defer program.Close()
			attached, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: program})
			if err != nil {
				t.Fatal(err)
			}
			defer attached.Close()
			for i := 0; i < 600; i++ {
				unix.Getpid()
			}
			if err := attached.Close(); err != nil {
				t.Fatal(err)
			}
			stats, err := collection.snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if collision {
				if stats.StackCollisions == 0 || stats.StackCaptureFailures < stats.StackCollisions || stats.RingBufferDropped != 0 {
					t.Fatalf("collision counters: %+v", stats)
				}
				// 4096-byte ring, 8-byte header + 8-byte record, one slot
				// reserved by the producer/consumer mask: 255 successes.
			} else if stats.RingBufferDropped != 600-255 || stats.StackCaptureFailures != 0 {
				t.Fatalf("ring counters: %+v", stats)
			}
		})
	}
}
