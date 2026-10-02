//go:build linux

package portal

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type tracepointField struct {
	offset int16
	size   int
	signed bool
}

var tracepointFormatLine = regexp.MustCompile(`field:([^;]+);\s*offset:(\d+);\s*size:(\d+);\s*signed:([01]);`)

// The running kernel, not a compiled-in ABI, determines each field offset.
// Only plain scalar integer fields are read; pointers, arrays and data_loc
// fields cannot be safely interpreted as scalar event values.
func parseTracepointFormat(format string, names []string) ([]tracepointField, error) {
	wanted := make(map[string]int, len(names))
	for i, name := range names {
		wanted[name] = i
	}
	fields := make([]tracepointField, len(names))
	seen := make(map[string]bool, len(names))
	for _, line := range strings.Split(format, "\n") {
		m := tracepointFormatLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		declaration := strings.TrimSpace(m[1])
		parts := strings.Fields(declaration)
		if len(parts) < 2 {
			continue
		}
		name := parts[len(parts)-1]
		i, ok := wanted[name]
		if !ok {
			continue
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate tracepoint field %q", name)
		}
		seen[name] = true
		offset, err1 := strconv.Atoi(m[2])
		size, err2 := strconv.Atoi(m[3])
		if strings.ContainsAny(declaration, "*[]:") || strings.Contains(declaration, "__data_loc") || strings.Contains(declaration, "__rel_loc") || err1 != nil || err2 != nil ||
			(size != 1 && size != 2 && size != 4 && size != 8) || offset < 0 || offset+size > 4096 {
			return nil, fmt.Errorf("unsupported tracepoint field %q", name)
		}
		fields[i] = tracepointField{offset: int16(offset), size: size, signed: m[4] == "1"}
	}
	for _, name := range names {
		if !seen[name] {
			return nil, fmt.Errorf("tracepoint format lacks scalar field %q", name)
		}
	}
	return fields, nil
}

func readTracepointFormat(category, name string, fields []string) ([]tracepointField, error) {
	// Identifiers have already been validated; no client-controlled path segments.
	var err error
	for _, root := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		var data []byte
		data, err = os.ReadFile(root + "/events/" + category + "/" + name + "/format")
		if err == nil {
			return parseTracepointFormat(string(data), fields)
		}
	}
	return nil, fmt.Errorf("read %s:%s tracepoint format: %w", category, name, err)
}

func tracepointInstructions(fields []tracepointField, eventsFD int) asm.Instructions {
	insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}
	for i, field := range fields {
		// TracePoint programs cannot directly load the common trace header
		// (including common_pid at offset 4). Probe reads also permit scalar
		// fields whose kernel-provided offsets are not naturally aligned.
		offset := int16(-8 * (len(fields) - i))
		insns = append(insns,
			asm.Mov.Imm(asm.R7, 0),
			asm.StoreMem(asm.RFP, offset, asm.R7, asm.DWord),
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, int32(offset)),
			asm.Mov.Imm(asm.R2, int32(field.size)),
			asm.Mov.Reg(asm.R3, asm.R6),
			asm.Add.Imm(asm.R3, int32(field.offset)),
			asm.FnProbeReadKernel.Call(),
			asm.JNE.Imm(asm.R0, 0, "exit"),
		)
	}
	insns = append(insns,
		asm.LoadMapPtr(asm.R1, eventsFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(-8*len(fields))),
		asm.Mov.Imm(asm.R3, int32(8*len(fields))),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return insns
}

func decodeTracepointRecord(raw []byte, spec TracepointFilter, fields []tracepointField) (Event, error) {
	if len(raw) != len(fields)*8 || len(fields) != len(spec.Fields) {
		return Event{}, errors.New("invalid eBPF tracepoint record")
	}
	values := make(map[string]json.Number, len(fields))
	for i, field := range fields {
		value := binary.NativeEndian.Uint64(raw[i*8 : (i+1)*8])
		if field.size < 8 {
			value &= (uint64(1) << (field.size * 8)) - 1
		}
		if field.signed {
			shift := uint(64 - field.size*8)
			values[spec.Fields[i]] = json.Number(strconv.FormatInt(int64(value<<shift)>>shift, 10))
		} else {
			values[spec.Fields[i]] = json.Number(strconv.FormatUint(value, 10))
		}
	}
	return Event{Time: time.Now().UTC(), Tracepoint: &TracepointEvent{Event: spec.Event, Fields: values}}, nil
}

func tracepointEvents(ctx context.Context, request MonitorRequest, emit func(Event) error) error {
	spec := request.Tracepoint
	if spec == nil {
		return errors.New("tracepoint spec required")
	}
	parts := strings.Split(spec.Event, ":")
	fields, err := readTracepointFormat(parts[0], parts[1], spec.Fields)
	if err != nil {
		return err
	}
	events, err := ebpf.NewMap(&ebpf.MapSpec{Name: "portal_trace", Type: ebpf.RingBuf, MaxEntries: 1 << 16})
	if err != nil {
		return fmt.Errorf("create eBPF tracepoint ring buffer: %w", err)
	}
	defer events.Close()
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "portal_trace", Type: ebpf.TracePoint, License: "GPL", Instructions: tracepointInstructions(fields, events.FD())})
	if err != nil {
		return fmt.Errorf("load eBPF tracepoint monitor: %w", err)
	}
	defer program.Close()
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return err
	}
	defer reader.Close()
	attached, err := link.Tracepoint(parts[0], parts[1], program, nil)
	if err != nil {
		return fmt.Errorf("attach eBPF tracepoint monitor: %w", err)
	}
	defer attached.Close()
	stop := context.AfterFunc(ctx, func() { reader.Close() })
	defer stop()
	for {
		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		}
		event, err := decodeTracepointRecord(record.RawSample, *spec, fields)
		if err != nil {
			return err
		}
		if request.matches(event) {
			if err := emit(event); err != nil {
				return err
			}
		}
	}
}
