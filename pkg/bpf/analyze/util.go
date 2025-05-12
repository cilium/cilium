// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"fmt"
	"iter"
	"maps"
	"slices"

	"github.com/cilium/ebpf/asm"
)

// A target is the destination of a jump instruction. It is initially known
// only by its raw instruction offset, and is later resolved to a logical
// index in the instruction stream. In subsequent passes, targets are
// also marked as leaders since they are the start of a new basic block.
type target struct {
	// index is the index of the logical instruction in the instruction stream.
	index int
	ins   *asm.Instruction
}

// rawTargets is a map of raw instruction offsets to targets. It is used to
// collect jump targets in the first pass of the basic block analysis.
//
// The raw instruction offset is the offset of the instruction in the raw
// bytecode, which is not necessarily the same as its index in
// [asm.Instructions] since some instructions can be larger than the standard
// instruction size (e.g. dword loads).
type rawTargets map[asm.RawInstructionOffset]*target

// add adds a raw instruction offset to the rawTargets map, marking the offset
// as the target of a jump instruction. If the offset is already present in the
// map, it is not added again.
func (rt rawTargets) add(raw asm.RawInstructionOffset) {
	_, ok := rt[raw]
	if !ok {
		rt[raw] = nil
	}
}

// resolve resolves a raw instruction offset to a fully-qualified target
// instruction at the given logical index. If the instruction was already
// resolved, does nothing.
func (rt rawTargets) resolve(raw asm.RawInstructionOffset, index int, ins *asm.Instruction) {
	if l := rt[raw]; l != nil {
		return
	}
	rt[raw] = &target{index, ins}
}

// get retrieves a target by its raw instruction offset. If the offset is not
// present in the map, it returns nil.
func (rt rawTargets) get(raw asm.RawInstructionOffset) *target {
	return rt[raw]
}

// keysSorted returns an iterator over the raw instruction offsets in sorted
// order. This is used to ensure that the raw instruction offsets are processed
// in the order they appear in the instruction stream, which is important for
// correctly resolving jump targets.
func (rt rawTargets) keysSorted() iter.Seq[asm.RawInstructionOffset] {
	return func(yield func(asm.RawInstructionOffset) bool) {
		for _, raw := range slices.Sorted(maps.Keys(rt)) {
			if !yield(raw) {
				return
			}
		}
	}
}

// jumpTarget calculates the target of a jump instruction based on the current
// raw instruction offset and the offset or constant present in the instruction.
// It returns the target offset and a boolean indicating whether the instruction
// is a jump instruction that causes a branch to another block.
//
// Returns false if the instruction does not branch.
func jumpTarget(raw asm.RawInstructionOffset, ins *asm.Instruction) (asm.RawInstructionOffset, bool) {
	op := ins.OpCode
	class := op.Class()
	jump := op.JumpOp()

	// Only jump instructions cause a branch to another block. Execution ends at
	// an exit instruction. And calls do not cause a branch, execution continues
	// after the call.
	if !class.IsJump() || jump == asm.Exit || jump == asm.Call {
		return 0, false
	}

	// Jump target is the current offset + the instruction offset + 1
	target := int64(raw) + int64(ins.Offset) + 1
	// A jump32 + JA is a 'long jump' with an offset larger than a u16. This is
	// encoded in the Constant field.
	if class == asm.Jump32Class && jump == asm.Ja {
		target = int64(raw) + ins.Constant + 1
	}

	if target < 0 {
		panic(fmt.Sprintf("negative jump target %d, raw: %d, insn: %s", target, raw, ins))
	}

	return asm.RawInstructionOffset(target), true
}

// canFallthrough checks if execution can fall through to the next instruction.
//
// An instruction can fall through if it is not a jump instruction, or if it is
// a jump instruction other than a jump-always and an exit.
func canFallthrough(ins *asm.Instruction) bool {
	if ins == nil {
		return false
	}
	if ins.OpCode.JumpOp() == asm.Ja ||
		ins.OpCode.JumpOp() == asm.Exit {
		return false
	}

	return true
}
