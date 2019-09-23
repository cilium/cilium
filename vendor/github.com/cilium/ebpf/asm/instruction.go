package asm

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/pkg/errors"
)

// InstructionSize is the size of a BPF instruction in bytes
const InstructionSize = 8

// Instruction is a single eBPF instruction.
type Instruction struct {
	OpCode    OpCode
	Dst       Register
	Src       Register
	Offset    int16
	Constant  int64
	Reference string
	Symbol    string
}

// Sym creates a symbol.
func (ins Instruction) Sym(name string) Instruction {
	ins.Symbol = name
	return ins
}

// Format implements fmt.Formatter.
func (ins Instruction) Format(f fmt.State, c rune) {
	if c != 'v' {
		fmt.Fprintf(f, "{UNRECOGNIZED: %c}", c)
		return
	}

	op := ins.OpCode

	if op == InvalidOpCode {
		fmt.Fprint(f, "INVALID")
		return
	}

	// Omit trailing space for Exit
	if op.JumpOp() == Exit {
		fmt.Fprint(f, op)
		return
	}

	fmt.Fprintf(f, "%v ", op)
	switch cls := op.Class(); cls {
	case LdClass, LdXClass, StClass, StXClass:
		switch op.Mode() {
		case ImmMode:
			fmt.Fprintf(f, "dst: %s imm: %d", ins.Dst, ins.Constant)
		case AbsMode:
			fmt.Fprintf(f, "imm: %d", ins.Constant)
		case IndMode:
			fmt.Fprintf(f, "dst: %s src: %s imm: %d", ins.Dst, ins.Src, ins.Constant)
		case MemMode:
			fmt.Fprintf(f, "dst: %s src: %s off: %d imm: %d", ins.Dst, ins.Src, ins.Offset, ins.Constant)
		case XAddMode:
			fmt.Fprintf(f, "dst: %s src: %s", ins.Dst, ins.Src)
		}

	case ALU64Class, ALUClass:
		fmt.Fprintf(f, "dst: %s ", ins.Dst)
		if op.ALUOp() == Swap || op.Source() == ImmSource {
			fmt.Fprintf(f, "imm: %d", ins.Constant)
		} else {
			fmt.Fprintf(f, "src: %s", ins.Src)
		}

	case JumpClass:
		switch jop := op.JumpOp(); jop {
		case Call:
			if ins.Src == R1 {
				// bpf-to-bpf call
				fmt.Fprint(f, ins.Constant)
			} else {
				fmt.Fprint(f, BuiltinFunc(ins.Constant))
			}

		default:
			fmt.Fprintf(f, "dst: %s off: %d ", ins.Dst, ins.Offset)
			if op.Source() == ImmSource {
				fmt.Fprintf(f, "imm: %d", ins.Constant)
			} else {
				fmt.Fprintf(f, "src: %s", ins.Src)
			}
		}
	}

	if ins.Reference != "" {
		fmt.Fprintf(f, " <%s>", ins.Reference)
	}
}

// Instructions is an eBPF program.
type Instructions []Instruction

func (insns Instructions) String() string {
	return fmt.Sprint(insns)
}

// SymbolOffsets returns the set of symbols and their offset in
// the instructions.
func (insns Instructions) SymbolOffsets() (map[string]int, error) {
	offsets := make(map[string]int)

	for i, ins := range insns {
		if ins.Symbol == "" {
			continue
		}

		if _, ok := offsets[ins.Symbol]; ok {
			return nil, errors.Errorf("duplicate symbol %s", ins.Symbol)
		}

		offsets[ins.Symbol] = i
	}

	return offsets, nil
}

// ReferenceOffsets returns the set of references and their offset in
// the instructions.
func (insns Instructions) ReferenceOffsets() map[string][]int {
	offsets := make(map[string][]int)

	for i, ins := range insns {
		if ins.Reference == "" {
			continue
		}

		offsets[ins.Reference] = append(offsets[ins.Reference], i)
	}

	return offsets
}

func (insns Instructions) marshalledOffsets() (map[string]int, error) {
	symbols := make(map[string]int)

	marshalledPos := 0
	for _, ins := range insns {
		currentPos := marshalledPos
		marshalledPos += ins.OpCode.marshalledInstructions()

		if ins.Symbol == "" {
			continue
		}

		if _, ok := symbols[ins.Symbol]; ok {
			return nil, errors.Errorf("duplicate symbol %s", ins.Symbol)
		}

		symbols[ins.Symbol] = currentPos
	}

	return symbols, nil
}

// Format implements fmt.Formatter.
//
// You can control indentation of symbols by
// specifying a width. Setting a precision controls the indentation of
// instructions.
// The default character is a tab, which can be overriden by specifying
// the ' ' space flag.
func (insns Instructions) Format(f fmt.State, c rune) {
	if c != 's' && c != 'v' {
		fmt.Fprintf(f, "{UNKNOWN FORMAT '%c'}", c)
		return
	}

	// Precision is better in this case, because it allows
	// specifying 0 padding easily.
	padding, ok := f.Precision()
	if !ok {
		padding = 1
	}

	indent := strings.Repeat("\t", padding)
	if f.Flag(' ') {
		indent = strings.Repeat(" ", padding)
	}

	symPadding, ok := f.Width()
	if !ok {
		symPadding = padding - 1
	}
	if symPadding < 0 {
		symPadding = 0
	}

	symIndent := strings.Repeat("\t", symPadding)
	if f.Flag(' ') {
		symIndent = strings.Repeat(" ", symPadding)
	}

	// Figure out how many digits we need to represent the highest
	// offset.
	highestOffset := 0
	for _, ins := range insns {
		highestOffset += ins.OpCode.marshalledInstructions()
	}
	offsetWidth := int(math.Ceil(math.Log10(float64(highestOffset))))

	offset := 0
	for _, ins := range insns {
		if ins.Symbol != "" {
			fmt.Fprintf(f, "%s%s:\n", symIndent, ins.Symbol)
		}
		fmt.Fprintf(f, "%s%*d: %v\n", indent, offsetWidth, offset, ins)
		offset += ins.OpCode.marshalledInstructions()
	}

	return
}

// Marshal encodes a BPF program into the kernel format.
func (insns Instructions) Marshal(w io.Writer, bo binary.ByteOrder) error {
	loadImmDW := LoadImmOp(DWord)

	absoluteOffsets, err := insns.marshalledOffsets()
	if err != nil {
		return err
	}

	num := 0
	for i, ins := range insns {
		if ins.OpCode == InvalidOpCode {
			return errors.Errorf("invalid operation at position %d", i)
		}

		isLoadImmDW := ins.OpCode == loadImmDW

		cons := int32(ins.Constant)
		switch {
		case isLoadImmDW:
			// Encode least significant 32bit first for 64bit operations.
			cons = int32(uint32(ins.Constant))

		case ins.OpCode.JumpOp() == Call && ins.Constant == -1:
			// Rewrite bpf to bpf call
			offset, ok := absoluteOffsets[ins.Reference]
			if !ok {
				return errors.Errorf("instruction %d: reference to missing symbol %s", i, ins.Reference)
			}

			cons = int32(offset - num - 1)

		case ins.OpCode.Class() == JumpClass && ins.Offset == -1:
			// Rewrite jump to label
			offset, ok := absoluteOffsets[ins.Reference]
			if !ok {
				return errors.Errorf("instruction %d: reference to missing symbol %s", i, ins.Reference)
			}

			ins.Offset = int16(offset - num - 1)
		}

		bpfi := bpfInstruction{
			ins.OpCode,
			newBPFRegisters(ins.Dst, ins.Src),
			ins.Offset,
			cons,
		}

		if err := binary.Write(w, bo, &bpfi); err != nil {
			return err
		}
		num++

		if !isLoadImmDW {
			continue
		}

		bpfi = bpfInstruction{
			Constant: int32(ins.Constant >> 32),
		}

		if err := binary.Write(w, bo, &bpfi); err != nil {
			return err
		}
		num++
	}
	return nil
}

// Unmarshal decodes a BPF program from the kernel format.
func (insns *Instructions) Unmarshal(r io.Reader, bo binary.ByteOrder) (map[uint64]int, error) {
	*insns = nil

	// Since relocations point at an offset, we need to keep track which
	// offset maps to which instruction.
	var (
		offsets = make(map[uint64]int)
		offset  uint64
	)
	for {
		offsets[offset] = len(*insns)

		var ins bpfInstruction
		err := binary.Read(r, bo, &ins)

		if err == io.EOF {
			return offsets, nil
		}

		if err != nil {
			return nil, errors.Errorf("invalid instruction at offset %x", offset)
		}

		requiredInsns := ins.OpCode.marshalledInstructions()
		offset += uint64(requiredInsns) * InstructionSize

		cons := int64(ins.Constant)
		if requiredInsns == 2 {
			var ins2 bpfInstruction
			if err := binary.Read(r, bo, &ins2); err != nil {
				return nil, errors.Errorf("invalid instruction at offset %x", offset)
			}
			if ins2.OpCode != 0 || ins2.Offset != 0 || ins2.Registers != 0 {
				return nil, errors.Errorf("instruction at offset %x: 64bit immediate has non-zero fields", offset)
			}
			cons = int64(uint64(uint32(ins2.Constant))<<32 | uint64(uint32(ins.Constant)))
		}

		*insns = append(*insns, Instruction{
			OpCode:   ins.OpCode,
			Dst:      ins.Registers.Dst(),
			Src:      ins.Registers.Src(),
			Offset:   ins.Offset,
			Constant: cons,
		})
	}
}

type bpfInstruction struct {
	OpCode    OpCode
	Registers bpfRegisters
	Offset    int16
	Constant  int32
}

type bpfRegisters uint8

func newBPFRegisters(dst, src Register) bpfRegisters {
	return bpfRegisters((src << 4) | (dst & 0xF))
}

func (r bpfRegisters) Dst() Register {
	return Register(r & 0xF)
}

func (r bpfRegisters) Src() Register {
	return Register(r >> 4)
}
