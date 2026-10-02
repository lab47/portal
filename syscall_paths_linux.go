//go:build linux

package portal

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/elastic/go-seccomp-bpf/arch"
)

var fileSyscalls = []string{"fsync", "fdatasync", "read", "write", "pread64", "pwrite64", "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2", "ftruncate", "fallocate"}

// Formatted sys_enter exposes args independently of architecture-specific
// pt_regs layouts. Capture only the first argument of known FD-based calls.
func syscallPathLayout() (int16, int16, []int, error) {
	fields, err := readTracepointFormat("raw_syscalls", "sys_enter", []string{"id"})
	if err != nil {
		return 0, 0, nil, err
	}
	if fields[0].size != 8 {
		return 0, 0, nil, fmt.Errorf("syscall paths require a 64-bit syscall ABI")
	}
	var data []byte
	for _, root := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		data, err = os.ReadFile(root + "/events/raw_syscalls/sys_enter/format")
		if err == nil {
			break
		}
	}
	if err != nil {
		return 0, 0, nil, err
	}
	args := int16(-1)
	for _, line := range strings.Split(string(data), "\n") {
		m := tracepointFormatLine.FindStringSubmatch(line)
		if m == nil || !strings.HasSuffix(strings.TrimSpace(m[1]), " args[6]") {
			continue
		}
		offset, e := strconv.Atoi(m[2])
		if e != nil || offset < 0 || offset > 4095 || m[3] != "48" {
			return 0, 0, nil, fmt.Errorf("unsupported syscall args layout")
		}
		args = int16(offset)
	}
	if args < 0 {
		return 0, 0, nil, fmt.Errorf("sys_enter lacks 64-bit args[6]")
	}
	table, err := arch.GetInfo(runtime.GOARCH)
	if err != nil {
		return 0, 0, nil, err
	}
	var ids []int
	for _, name := range fileSyscalls {
		if id, ok := table.SyscallNames[name]; ok {
			ids = append(ids, id)
		}
	}
	return fields[0].offset, args, ids, nil
}

func appendSyscallFD(i asm.Instructions, offset, args int16, ids []int) asm.Instructions {
	i = append(i, asm.Mov.Imm(asm.R0, 0), asm.StoreMem(asm.RFP, offset, asm.R0, asm.DWord))
	for _, id := range ids {
		i = append(i, asm.JEq.Imm32(asm.R8, int32(id), "file_fd"))
	}
	i = append(i, asm.Ja.Label("file_fd_done"), asm.Mov.Reg(asm.R1, asm.RFP).WithSymbol("file_fd"), asm.Add.Imm(asm.R1, int32(offset)), asm.Mov.Imm(asm.R2, 4), asm.Mov.Reg(asm.R3, asm.R6), asm.Add.Imm(asm.R3, int32(args)), asm.FnProbeReadKernel.Call(), asm.JNE.Imm(asm.R0, 0, "file_fd_done"), asm.StoreImm(asm.RFP, offset+4, 1, asm.Word), asm.Mov.Imm(asm.R0, 0).WithSymbol("file_fd_done"))
	return i
}

func resolveSyscallFile(raw []byte, event *Event) {
	if binary.NativeEndian.Uint32(raw[4:8]) != 1 {
		return
	}
	f := &SyscallFile{FD: int32(binary.NativeEndian.Uint32(raw[:4]))}
	event.File = f
	if f.FD < 0 {
		f.Error = "invalid file descriptor"
		return
	}
	if err := verifyHostPID(event.TID); err != nil {
		f.Error = err.Error()
		return
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", event.TID, f.FD))
	if err != nil {
		f.Error = err.Error()
		return
	}
	f.Path = path
}
