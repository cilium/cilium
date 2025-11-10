// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"fmt"
	"slices"

	"github.com/cilium/ebpf/asm"
)

// A target is the destination of a jump instruction. It is initially known only
// by its raw instruction offset and is resolved to a logical instruction in a
// second pass. It also holds a list of branches (jump instructions) that target
// it.
//
// The raw instruction offset is the offset of the instruction in the raw
// bytecode, which is not necessarily the same as its index in
// [asm.Instructions] since some instructions can be larger than the standard
// instruction size (e.g. dword loads).
type target struct {
	raw      asm.RawInstructionOffset
	branches []*asm.Instruction
}

func (t *target) append(branch *asm.Instruction) {
	t.branches = append(t.branches, branch)
}

// rawTargets tracks jump target instructions by their raw instruction offsets
// and branch instructions pointing to it.
type rawTargets struct {
	targets []target
}

// add marks the given raw offset as the target of a jump instruction. If the
// offset was seen before, it is not added again. fthrough should be set to the
// instruction following the jump instruction, or nil if there is none.
//
// Offsets are encountered in random order while iterating instructions, since
// jumps can go forward and backward, and sometimes jump over other branches.
// targets are kept in a sorted queue to allow efficient resolution later.
func (rt *rawTargets) add(jump *asm.Instruction, tgt asm.RawInstructionOffset) {
	insertIdx, found := slices.BinarySearchFunc(rt.targets, tgt, func(t target, r asm.RawInstructionOffset) int {
		if t.raw < r {
			return -1
		}
		if t.raw > r {
			return 1
		}
		return 0
	})

	if found {
		rt.targets[insertIdx].append(jump)
		return
	}

	rt.targets = slices.Insert(
		rt.targets,
		insertIdx,
		target{
			raw:      tgt,
			branches: []*asm.Instruction{jump},
		})
}

// resolve needs to be called sequentially for every instruction in a program
// after all jump targets have been added using [rawTargets.add].
//
// The given raw offset is matched against the first entry in rt. If it matches,
// all jumps pointing to this instruction get their branch targets updated to
// point to tgt. tgtPrev turns into an edge falling through to tgt.
//
// Resolved targets are popped from the head of the list.
func (rt *rawTargets) resolve(raw asm.RawInstructionOffset, tgt, tgtPrev *asm.Instruction) {
	if len(rt.targets) == 0 {
		return
	}

	target := rt.targets[0]
	if target.raw != raw {
		return
	}

	for _, branch := range target.branches {
		setBranchTarget(branch, tgt, tgtPrev)
	}

	rt.targets = rt.targets[1:]
}

// previous returns the instruction preceding the current instruction in the
// iterator, or nil if there is none.
func previous(iter *asm.InstructionIterator, insns asm.Instructions) *asm.Instruction {
	if iter.Index-1 >= 0 {
		return &insns[iter.Index-1]
	}
	return nil
}

// next returns the instruction following the current instruction in the
// iterator, or nil if there is none.
func next(iter *asm.InstructionIterator, insns asm.Instructions) *asm.Instruction {
	if iter.Index+1 < len(insns) {
		return &insns[iter.Index+1]
	}
	return nil
}

// jumpTarget calculates the target of a jump instruction based on the current
// raw instruction offset and the offset or constant present in the instruction.
// It returns the target offset and a boolean indicating whether the instruction
// is a jump instruction that causes a branch to another block.
//
// Returns false if the instruction does not branch.
func jumpTarget(raw asm.RawInstructionOffset, ins *asm.Instruction) (asm.RawInstructionOffset, error) {
	op := ins.OpCode
	class := op.Class()
	jump := op.JumpOp()

	// Only jump instructions cause a branch to another block. Execution ends at
	// an exit instruction. And calls do not cause a branch, execution continues
	// after the call.
	if !class.IsJump() || jump == asm.Exit || jump == asm.Call {
		return 0, fmt.Errorf("not a jump: %s", ins)
	}

	// Jump target is the current offset + the instruction offset + 1
	target := int64(raw) + int64(ins.Offset) + 1
	// A jump32 + JA is a 'long jump' with an offset larger than a u16. This is
	// encoded in the Constant field.
	if class == asm.Jump32Class && jump == asm.Ja {
		target = int64(raw) + ins.Constant + 1
	}

	if target < 0 {
		return 0, fmt.Errorf("jump target before start of program: %d, raw: %d, insn: %s", target, raw, ins)
	}

	return asm.RawInstructionOffset(target), nil
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

// bpfCallers maps bpf2bpf function names to Blocks that refer to them.
type bpfCallers map[string][]*Block

// record is to be called for each instruction in a block to record function
// references found in the instructions.
//
// Blocks that contain function references get their callees populated in a
// later call to [bpfCallers.connect].
func (bc bpfCallers) record(ins *asm.Instruction, caller *Block) {
	if !ins.IsFunctionReference() {
		return
	}

	if sym := ins.Reference(); sym != "" {
		bc[sym] = append(bc[sym], caller)
	}
}

// connect populates the [Block.calls] field of all Blocks that contain function
// references with the corresponding callee Blocks.
func (bc bpfCallers) connect(blocks Blocks) {
	for _, block := range blocks {
		// Check if the block represents the start of a function.
		callee := block.sym
		if callee == "" {
			continue
		}

		// Find all callers of this function.
		callers := bc[callee]
		if callers == nil {
			continue
		}

		// Link callers to this callee block.
		for _, caller := range callers {
			caller.calls = append(caller.calls, block)
		}
	}
}
