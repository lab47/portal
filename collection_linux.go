//go:build linux

package portal

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const taskIdentitySize = 24 // pid/tid plus 16-byte current task comm
const (
	collectionRingDropped = iota
	collectionStackFailed
	collectionStackCollision
	collectionPairingFailed
	collectionUnmatchedExit
	collectionCounterCount
)

type collectionState struct{ counters *ebpf.Map }

func newCollectionState() (*collectionState, error) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "portal_loss", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: collectionCounterCount})
	if err != nil {
		return nil, fmt.Errorf("create collection counters: %w", err)
	}
	return &collectionState{counters: m}, nil
}

func (s *collectionState) close() {
	if s != nil {
		s.counters.Close()
	}
}

// Uses a reserved scratch slot below all event records; helpers preserve R6–R9.
func appendCollectionCounter(insns asm.Instructions, s *collectionState, counter int, label string) asm.Instructions {
	if s == nil {
		return insns
	}
	return append(insns,
		asm.StoreImm(asm.RFP, -480, int64(counter), asm.Word),
		asm.LoadMapPtr(asm.R1, s.counters.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -480),
		asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, label),
		asm.Mov.Imm(asm.R1, 1), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(label),
	)
}

func appendRingLoss(insns asm.Instructions, s *collectionState) asm.Instructions {
	if s == nil {
		return insns
	}
	insns = append(insns, asm.JSGE.Imm(asm.R0, 0, "ring_loss_done"))
	return appendCollectionCounter(insns, s, collectionRingDropped, "ring_loss_done")
}

func appendTaskIdentity(insns asm.Instructions, offset int16) asm.Instructions {
	return append(insns,
		asm.FnGetCurrentPidTgid.Call(), asm.StoreMem(asm.RFP, offset, asm.R0, asm.DWord),
		asm.Mov.Imm(asm.R0, 0), asm.StoreMem(asm.RFP, offset+8, asm.R0, asm.DWord), asm.StoreMem(asm.RFP, offset+16, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, int32(offset+8)),
		asm.Mov.Imm(asm.R2, 16), asm.FnGetCurrentComm.Call(),
	)
}

func decodeTaskIdentity(raw []byte, event *Event) {
	pidTID := binary.NativeEndian.Uint64(raw[:8])
	event.PID, event.TID = uint32(pidTID>>32), uint32(pidTID)
	event.Name = string(bytes.TrimRight(raw[8:24], "\x00"))
}

func (s *collectionState) snapshot() (*CollectionStats, error) {
	values := make([]uint64, collectionCounterCount)
	for i := range values {
		key := uint32(i)
		if err := s.counters.Lookup(&key, &values[i]); err != nil {
			return nil, err
		}
	}
	return &CollectionStats{RingBufferDropped: values[0], StackCaptureFailures: values[1], StackCollisions: values[2], PairingFailures: values[3], UnmatchedExits: values[4]}, nil
}

func (s *collectionState) report(event *Event) error {
	stats, err := s.snapshot()
	if err == nil {
		event.Collection = stats
	}
	return err
}
