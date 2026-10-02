//go:build linux

package portal

import (
	"context"
	"encoding/binary"
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

type diskField struct {
	offset int16
	size   int
}

var traceField = regexp.MustCompile(`field:[^;]*\b(dev|sector|nr_sector|rwbs)(?:\[(\d+)\])?;\s*offset:(\d+);\s*size:(\d+);`)

// Tracepoint context offsets are kernel-specific; reject formats we cannot read.
func parseDiskFormat(format string) (map[string]diskField, error) {
	fields := make(map[string]diskField)
	for _, line := range strings.Split(format, "\n") {
		match := traceField.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		offset, err := strconv.Atoi(match[3])
		if err != nil || offset < 0 || offset > 4095 {
			return nil, fmt.Errorf("invalid %s offset", match[1])
		}
		size, err := strconv.Atoi(match[4])
		if err != nil || (match[1] == "sector" && size != 8) ||
			((match[1] == "dev" || match[1] == "nr_sector") && size != 4) ||
			(match[1] == "rwbs" && (size < 1 || size > 32 || match[2] != strconv.Itoa(size))) {
			return nil, fmt.Errorf("unsupported %s size", match[1])
		}
		if _, exists := fields[match[1]]; exists {
			return nil, fmt.Errorf("duplicate %s field", match[1])
		}
		fields[match[1]] = diskField{offset: int16(offset), size: size}
	}
	for _, name := range []string{"dev", "sector", "nr_sector", "rwbs"} {
		if _, ok := fields[name]; !ok {
			return nil, fmt.Errorf("block_rq_issue lacks %s field", name)
		}
	}
	return fields, nil
}

func readDiskFormat() (map[string]diskField, error) {
	var err error
	for _, path := range []string{
		"/sys/kernel/tracing/events/block/block_rq_issue/format",
		"/sys/kernel/debug/tracing/events/block/block_rq_issue/format",
	} {
		var data []byte
		data, err = os.ReadFile(path)
		if err == nil {
			return parseDiskFormat(string(data))
		}
	}
	return nil, fmt.Errorf("read block_rq_issue tracepoint format: %w", err)
}

func diskInstructions(fields map[string]diskField, eventsFD int, filter *DiskFilter, collections ...*collectionState) asm.Instructions {
	var collection *collectionState
	if len(collections) != 0 {
		collection = collections[0]
	}
	insns := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R7, asm.R6, fields["dev"].offset, asm.Word),
	}
	if filter != nil && filter.Device != 0 {
		insns = append(insns, asm.JNE.Imm32(asm.R7, int32(filter.Device), "exit"))
	}
	insns = append(insns, asm.LoadMem(asm.R8, asm.R6, fields["rwbs"].offset, asm.Byte))
	if filter != nil && filter.Operation != "" {
		ops := map[string]int32{"read": 'R', "write": 'W', "discard": 'D', "flush": 'F'}
		insns = append(insns, asm.JNE.Imm(asm.R8, ops[filter.Operation], "exit"))
	}
	// Capture current before R6 is reused for nr_sector below.
	insns = appendTaskIdentity(insns, -48)
	insns = append(insns,
		asm.LoadMem(asm.R9, asm.R6, fields["sector"].offset, asm.DWord),
		asm.LoadMem(asm.R6, asm.R6, fields["nr_sector"].offset, asm.Word),
		asm.StoreMem(asm.RFP, -24, asm.R7, asm.Word),
		asm.StoreMem(asm.RFP, -20, asm.R6, asm.Word),
		asm.StoreMem(asm.RFP, -16, asm.R9, asm.DWord),
		asm.Mov.Imm(asm.R0, 0),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.StoreMem(asm.RFP, -8, asm.R8, asm.Byte),
		asm.LoadMapPtr(asm.R1, eventsFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -48),
		asm.Mov.Imm(asm.R3, 48),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
	)
	insns = appendRingLoss(insns, collection)
	insns = append(insns, asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
	return insns
}

func decodeDiskRecord(raw []byte) (Event, error) {
	if len(raw) != taskIdentitySize+24 {
		return Event{}, errors.New("invalid eBPF disk record")
	}
	event := Event{Time: time.Now().UTC()}
	decodeTaskIdentity(raw[:taskIdentitySize], &event)
	raw = raw[taskIdentitySize:]
	op := map[byte]string{'R': "read", 'W': "write", 'D': "discard", 'F': "flush"}[raw[16]]
	if op == "" {
		op = "other"
	}
	event.Disk = &DiskEvent{
		Device: binary.NativeEndian.Uint32(raw[:4]), Sectors: binary.NativeEndian.Uint32(raw[4:8]),
		Sector: binary.NativeEndian.Uint64(raw[8:16]), Operation: op,
	}
	return event, nil
}

func diskEvents(ctx context.Context, request MonitorRequest, emit func(Event) error) error {
	if request.Phase == "completion" {
		return diskCompletionEvents(ctx, request, emit)
	}
	fields, err := readDiskFormat()
	if err != nil {
		return err
	}
	events, err := ebpf.NewMap(&ebpf.MapSpec{Name: "portal_disk", Type: ebpf.RingBuf, MaxEntries: 1 << 16})
	if err != nil {
		return fmt.Errorf("create eBPF disk ring buffer: %w", err)
	}
	defer events.Close()
	collection, err := newCollectionState()
	if err != nil {
		return err
	}
	defer collection.close()
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "portal_disk_issue", Type: ebpf.TracePoint, License: "GPL", Instructions: diskInstructions(fields, events.FD(), request.Disk, collection)})
	if err != nil {
		return fmt.Errorf("load eBPF disk monitor: %w", err)
	}
	defer program.Close()
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return err
	}
	defer reader.Close()
	attached, err := link.Tracepoint("block", "block_rq_issue", program, nil)
	if err != nil {
		return fmt.Errorf("attach eBPF disk monitor: %w", err)
	}
	defer attached.Close()
	stop := context.AfterFunc(ctx, func() { reader.Close() })
	defer stop()
	for {
		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ringbuf.ErrClosed) {
				if err := attached.Close(); err != nil {
					return err
				}
				final := Event{Kind: "collection_stats", Time: time.Now().UTC()}
				if err := collection.report(&final); err != nil {
					return err
				}
				return emit(final)
			}
			return err
		}
		event, err := decodeDiskRecord(record.RawSample)
		if err != nil {
			return err
		}
		if err := collection.report(&event); err != nil {
			return err
		}
		if request.matches(event) {
			if err := emit(event); err != nil {
				return err
			}
		}
	}
}
