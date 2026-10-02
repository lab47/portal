//go:build linux

package portal

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// syscallEvents attaches one raw tracepoint per subscription. The program
// emits a fixed-size record: pid/tid (u64), syscall number (u64).
func syscallEvents(ctx context.Context, request MonitorRequest, emit func(Event) error) error {
	events, err := ebpf.NewMap(&ebpf.MapSpec{Name: "portal_events", Type: ebpf.RingBuf, MaxEntries: 1 << 16})
	if err != nil {
		return fmt.Errorf("create eBPF ring buffer: %w", err)
	}
	defer events.Close()
	stacks, err := newStackCaptureState(request.Stacks)
	if err != nil {
		return err
	}
	defer stacks.close()
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
	}
	if request.PID != 0 {
		insns = append(insns,
			asm.Mov.Reg(asm.R1, asm.R0),
			asm.RSh.Imm(asm.R1, 32),
			asm.JNE.Imm32(asm.R1, int32(request.PID), "exit"),
		)
	}
	// A non-root server never exports events from other local accounts.
	if os.Geteuid() != 0 {
		insns = append(insns,
			asm.FnGetCurrentUidGid.Call(),
			asm.JNE.Imm32(asm.R0, int32(os.Geteuid()), "exit"), // low 32 bits are UID; high 32 are GID
		)
	}
	insns = append(insns, asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord)) // raw tracepoint args[1] = syscall ID
	if len(request.Syscalls) != 0 {
		for _, id := range request.Syscalls {
			insns = append(insns, asm.JEq.Imm32(asm.R8, int32(id), "emit"))
		}
		insns = append(insns, asm.Ja.Label("exit"))
	}
	recordSize := 16
	emitAtStackCapture := false
	if stacks != nil {
		captureStart := len(insns)
		insns = appendStackCapture(insns, asm.R6, int16(-16-stacks.recordSize()), stacks)
		insns[captureStart] = insns[captureStart].WithSymbol("emit")
		emitAtStackCapture = true
		recordSize += stacks.recordSize()
	}
	pidStore := asm.StoreMem(asm.RFP, -16, asm.R7, asm.DWord)
	if !emitAtStackCapture {
		pidStore = pidStore.WithSymbol("emit")
	}
	insns = append(insns,
		pidStore,
		asm.StoreMem(asm.RFP, -8, asm.R8, asm.DWord),
		asm.LoadMapPtr(asm.R1, events.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(-recordSize)),
		asm.Mov.Imm(asm.R3, int32(recordSize)),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "portal_sys_enter", Type: ebpf.RawTracepoint, License: "GPL", Instructions: insns})
	if err != nil {
		return fmt.Errorf("load eBPF syscall monitor: %w", err)
	}
	defer program.Close()
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return err
	}
	defer reader.Close()
	attached, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: program})
	if err != nil {
		return fmt.Errorf("attach eBPF syscall monitor: %w", err)
	}
	defer attached.Close()
	stop := context.AfterFunc(ctx, func() { reader.Close() })
	defer stop()
	for {
		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		}
		if len(record.RawSample) != recordSize {
			return errors.New("invalid eBPF syscall record")
		}
		base := len(record.RawSample) - 16
		pidTID := binary.NativeEndian.Uint64(record.RawSample[base : base+8])
		event := Event{Time: time.Now().UTC(), PID: uint32(pidTID >> 32), TID: uint32(pidTID), Syscall: int(binary.NativeEndian.Uint64(record.RawSample[base+8:]))}
		if stacks != nil {
			if err := stacks.decode(ctx, record.RawSample[:base], &event); err != nil {
				return err
			}
		}
		if request.matches(event) {
			if err := emit(event); err != nil {
				return err
			}
		}
	}
}
