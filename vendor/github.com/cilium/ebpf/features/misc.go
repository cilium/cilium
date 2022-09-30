package features

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

func init() {
	miscs.miscTypes = make(map[miscType]error)
}

var (
	miscs miscCache
)

type miscCache struct {
	sync.Mutex
	miscTypes map[miscType]error
}

type miscType uint32

const (
	// largeInsn support introduced in Linux 5.2
	// commit c04c0d2b968ac45d6ef020316808ef6c82325a82
	largeInsn miscType = iota
	// boundedLoops support introduced in Linux 5.3
	// commit 2589726d12a1b12eaaa93c7f1ea64287e383c7a5
	boundedLoops
	// v2ISA support introduced in Linux 4.14
	// commit 92b31a9af73b3a3fc801899335d6c47966351830
	v2ISA
	// v3ISA support introduced in Linux 5.1
	// commit 092ed0968bb648cd18e8a0430cd0a8a71727315c
	v3ISA
)

const (
	maxInsns = 4096
)

// HaveLargeInstructions probes the running kernel if more than 4096 instructions
// per program are supported.
//
// See the package documentation for the meaning of the error return value.
func HaveLargeInstructions() error {
	return probeMisc(largeInsn)
}

// HaveBoundedLoops probes the running kernel if bounded loops are supported.
//
// See the package documentation for the meaning of the error return value.
func HaveBoundedLoops() error {
	return probeMisc(boundedLoops)
}

// HaveV2ISA probes the running kernel if instructions of the v2 ISA are supported.
//
// See the package documentation for the meaning of the error return value.
func HaveV2ISA() error {
	return probeMisc(v2ISA)
}

// HaveV3ISA probes the running kernel if instructions of the v3 ISA are supported.
//
// See the package documentation for the meaning of the error return value.
func HaveV3ISA() error {
	return probeMisc(v3ISA)
}

// probeMisc checks the kernel for a given supported misc by creating
// a specialized program probe and loading it.
func probeMisc(mt miscType) (err error) {
	defer func() {
		// This closure modifies a named return variable.
		err = wrapProbeErrors(err)
	}()

	miscs.Lock()
	defer miscs.Unlock()
	err, ok := miscs.miscTypes[mt]
	if ok {
		return err
	}

	attr, err := createMiscProbeAttr(mt)
	if err != nil {
		return fmt.Errorf("couldn't create the attributes for the probe: %w", err)
	}

	fd, err := sys.ProgLoad(attr)
	if err == nil {
		fd.Close()
	}

	switch {
	// EINVAL occurs when attempting to create a program with an unknown type.
	// E2BIG occurs when ProgLoadAttr contains non-zero bytes past the end
	// of the struct known by the running kernel, meaning the kernel is too old
	// to support the given map type.
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.E2BIG):
		err = ebpf.ErrNotSupported
	}

	miscs.miscTypes[mt] = err

	return err
}

func createMiscProbeAttr(mt miscType) (*sys.ProgLoadAttr, error) {
	var insns asm.Instructions
	switch mt {
	case largeInsn:
		for i := 0; i < maxInsns; i++ {
			insns = append(insns, asm.Mov.Imm(asm.R0, 1))
		}
		insns = append(insns, asm.Return())
	case boundedLoops:
		insns = asm.Instructions{
			asm.Mov.Imm(asm.R0, 10),
			asm.Sub.Imm(asm.R0, 1).WithSymbol("loop"),
			asm.JNE.Imm(asm.R0, 0, "loop"),
			asm.Return(),
		}
	case v2ISA:
		insns = asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.JLT.Imm(asm.R0, 0, "exit"),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return().WithSymbol("exit"),
		}
	case v3ISA:
		insns = asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.JLT.Imm32(asm.R0, 0, "exit"),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return().WithSymbol("exit"),
		}
	default:
		return nil, fmt.Errorf("misc probe %d not implemented", mt)
	}

	buf := bytes.NewBuffer(make([]byte, 0, insns.Size()))
	if err := insns.Marshal(buf, internal.NativeEndian); err != nil {
		return nil, err
	}

	bytecode := buf.Bytes()
	instructions := sys.NewSlicePointer(bytecode)

	return &sys.ProgLoadAttr{
		ProgType: sys.BPF_PROG_TYPE_SOCKET_FILTER,
		Insns:    instructions,
		InsnCnt:  uint32(len(bytecode) / asm.InstructionSize),
		License:  sys.NewStringPointer("MIT"),
	}, nil
}
