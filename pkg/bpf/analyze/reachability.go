// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"errors"
	"fmt"
	"unique"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Reachability performs static analysis on BPF programs to determine which code
// paths are reachable based on runtime constants. It evaluates conditional
// branches that depend on constant configuration values (like those used in
// CONFIG() macros) to predict whether branches will be taken at runtime.
//
// The analysis works by identifying patterns where a value is loaded from a
// global data map, dereferenced, and then used in a conditional branch. When
// such a pattern is found with a constant value, the branch outcome can be
// predicted statically. This allows for dead code elimination to prune unused
// maps and tail calls.
//
// The algorithm works as follows:
//
// 1. Start from the first block of the BPF program. Check if the last
// instruction is a branch instruction that compares a register against an
// immediate (embedded in bytecode) value. For example:
//
//	J{OP}Imm dst: Ry off:{relative jump offset} imm: {constant value}
//
// 2. If such an instruction is found, backtrack to find a pointer dereference
// targeting the Ry register used in the branch instruction. If the top of the
// current block is hit, roll over to the predecessor block if the block has a
// single predecessor. For example:
//
// 	LdXMem{B,H,W,DW} dst: Ry src: Rx off: 0
//
// 3. If the dereference is found, backtrack further to find a map load
// instruction that populates the Rx register. Similar to the previous case,
// backtracking continues in the predecessor if needed. For example:
//
//	LoadMapValue dst: Rx, fd: 0 off: {offset of variable} <{name of global data map}>
//
// 4. If a map load instruction is found, look up which variable it refers to in
// CollectionSpec.Variables. Only variables declared `const` qualify for branch
// prediction, otherwise its value may change at runtime and the branch cannot
// be predicted.
//
// 5. If the variable is found and its value is constant, the branch instruction
// is interpreted and a verdict is made whether the branch is always taken
// or never taken.
//
// This process is repeated, recursively, exactly once for each block in the
// BPF program. The analysis is conservative, meaning that if any part of the
// pattern is not found, the branch is considered unpredictable and both the
// branch and fallthrough blocks are visited.
//
// If a block is visited, it is implicitly marked as live, since it means that
// at least one of its predecessors is live, making it reachable from the root
// (first block) of the BPF program.
//
// Once the reachability analysis is complete, the program's instructions can be
// iterated using a special iterator that provides a boolean with every
// instruction to indicate whether the instruction is reachable or not. This
// makes it straightforward to mark live and/or unreachable resources like maps
// and tail calls referenced by the instructions in a single pass.

// TODO(tb): This is kind of silly. Let's just put a NewVariableSpec in the lib
// to make this kind of testing possible. They are accessors anyway, though
// they're copied during CollectionSpec.Copy(), which will need some extra
// attention. Bounds checks also need to be performed in NewVariableSpec.
// Make a variable spec interface that is satisfied by the ebpf.VariableSpec
// This makes testing easier since we can create a mock variable spec.
var _ VariableSpec = (*ebpf.VariableSpec)(nil)

type VariableSpec interface {
	MapName() string
	Offset() uint64
	Size() uint64
	Get(out any) error
	Constant() bool
}

func VariableSpecs(variables map[string]*ebpf.VariableSpec) map[string]VariableSpec {
	variablesMap := make(map[string]VariableSpec)
	for name, varSpec := range variables {
		variablesMap[name] = varSpec
	}
	return variablesMap
}

// Reachability returns a copy of blocks with populated reachability information.
//
// Reachability of blocks is determined by predicting branches on BPF runtime
// constants. A subsequent call to [Blocks.LiveInstructions] will iterate over
// all instructions deemed reachable given the set of VariableSpecs.
//
// Given a piece of code like:
//
//	if (CONFIG(enable_feature_a)) {
//
// or
//
//	if (CONFIG(number_of_something) > 5) {
//
// It looks for the following bytecode:
//
//	LoadMapValue dst: Rx, fd: 0 off: {offset of variable} <{name of global data map}>
//	LdXMem{B,H,W,DW} dst: Ry src: Rx off: 0
//	J{OP}IMM dst: Ry off:{relative jump offset} imm: {constant value}
func Reachability(blocks *Blocks, insns asm.Instructions, variables map[string]VariableSpec) (*Blocks, error) {
	if blocks == nil || blocks.count() == 0 {
		return nil, errors.New("nil or empty blocks")
	}

	if len(insns) == 0 {
		return nil, errors.New("nil or empty instructions")
	}

	if len(blocks.l) != 0 {
		return nil, errors.New("reachability already computed")
	}

	// Copy Blocks to avoid modifying the original, since they're often stored in
	// instruction metadata in a cached CollectionSpec.
	blocks = blocks.Copy()

	// Variables in the CollectionSpec are identified by name. However,
	// instructions refer to variables by map name and offset. Build a reverse
	// lookup map. This notably includes references to non-constant variables,
	// which will be rejected later in the branch evaluation logic. They are
	// included here to ensure that the reachability analysis is conclusive.
	vars := make(map[mapOffset]VariableSpec)
	for _, v := range variables {
		vars[mapOffset{
			mapName: unique.Make(v.MapName()),
			offset:  v.Offset(),
		}] = v
	}

	live := newBitmap(uint64(blocks.count()))
	jumps := newBitmap(uint64(blocks.count()))

	// Start recursing at first block since it is always live.
	if err := visitBlock(blocks.first(), insns, vars, live, jumps); err != nil {
		return nil, fmt.Errorf("predicting blocks: %w", err)
	}

	blocks.l = live
	blocks.j = jumps

	return blocks, nil
}

// findBranch pulls exactly one instruction and checks if it's a branch
// instruction comparing a register against an immediate value. Returns
// the instruction if it met the criteria, nil otherwise.
func findBranch(pull func() (*asm.Instruction, bool)) *asm.Instruction {
	// Only the last instruction of a block can be a branch instruction.
	branch, ok := pull()
	if !ok {
		return nil
	}

	switch branch.OpCode.JumpOp() {
	case asm.Exit, asm.Call, asm.Ja, asm.InvalidJumpOp:
		return nil
	}

	// Only consider jumps that check the dst register against an immediate value.
	if branch.OpCode.Source() != asm.ImmSource {
		return nil
	}

	return branch
}

// findDereference pulls instructions until it finds a memory load (dereference)
// into the given dst register.
//
// Since all CONFIG() variables are `volatile`, the compiler should emit a
// dereference before every branch instruction. These typically occur in the
// same basic block, albeit with a few unrelated instructions in between.
func findDereference(pull func() (*asm.Instruction, bool), dst asm.Register) *asm.Instruction {
	for ins, ok := pull(); ok; ins, ok = pull() {
		op := ins.OpCode
		if op.Class().IsLoad() && op.Mode() == asm.MemMode && ins.Dst == dst {
			return ins
		}

		if ins.Dst == dst {
			// Found a non-load instruction that clobbers the register used by the
			// branch instruction. This doesn't match the pattern we're looking for,
			// so stop looking.
			return nil
		}
	}

	return nil
}

// findMapLoad pulls instructions until it finds a map load instruction that
// populates the given src register.
//
// Even though CONFIG() variables are declared volatile, the compiler may still
// decide to reuse the register containing the map pointer for multiple
// dereferences. This often occurs in a predecessor block, so the pull function
// must support predecessor traversal.
//
// Note: the compiler should favor reconstructing the map pointer over spilling
// to the stack, so we don't consider stack spilling.
func findMapLoad(pull func() (*asm.Instruction, bool), src asm.Register) *asm.Instruction {
	for ins, ok := pull(); ok; ins, ok = pull() {
		if ins.Dst == src {
			if ins.IsLoadFromMap() {
				return ins
			}

			// Register got clobbered, stop looking.
			return nil
		}
	}

	return nil
}

type mapOffset struct {
	mapName unique.Handle[string]
	offset  uint64
}

// unpredictableBlock is called when the branch cannot be predicted. It visits
// both the branch and fallthrough blocks.
func unpredictableBlock(b *Block, insns asm.Instructions, vars map[mapOffset]VariableSpec, live, jumps bitmap) error {
	if err := visitBlock(b.branch, insns, vars, live, jumps); err != nil {
		return fmt.Errorf("visiting branch block %d: %w", b.branch.id, err)
	}
	if err := visitBlock(b.fthrough, insns, vars, live, jumps); err != nil {
		return fmt.Errorf("visiting fallthrough block %d: %w", b.fthrough.id, err)
	}
	return nil
}

// visitBlock recursively visits a block and its successors to determine
// reachability based on the branch instructions and the provided vars.
func visitBlock(b *Block, insns asm.Instructions, vars map[mapOffset]VariableSpec, live, jumps bitmap) error {
	if b == nil {
		return nil
	}

	// Don't evaluate the same block twice, this would lead to an infinite loop.
	// A live block implies a visited block.
	if live.get(b.id) {
		return nil
	}
	live.set(b.id, true)

	pull := b.backward(insns)

	branch := findBranch(pull)
	if branch == nil {
		return unpredictableBlock(b, insns, vars, live, jumps)
	}

	deref := findDereference(pull, branch.Dst)
	if deref == nil {
		return unpredictableBlock(b, insns, vars, live, jumps)
	}

	load := findMapLoad(pull, deref.Src)
	if load == nil {
		return unpredictableBlock(b, insns, vars, live, jumps)
	}

	// TODO(tb): evalBranch doesn't currently take the deref's offset field into
	// account so it can't deal with variables over 8 bytes in size. Improve it
	// to be more robust and remove this limitation.
	vs := lookupVariable(load, vars)
	if vs == nil || !vs.Constant() || vs.Size() > 8 {
		return unpredictableBlock(b, insns, vars, live, jumps)
	}

	jump, err := evalBranch(branch, vs)
	if err != nil {
		return fmt.Errorf("evaluating branch of block %d: %w", b.id, err)
	}

	// If the branch is always taken, only visit the branch target.
	if jump {
		jumps.set(b.id, true)
		return visitBlock(b.branch, insns, vars, live, jumps)
	}

	// Otherwise, only visit the fallthrough target.
	return visitBlock(b.fthrough, insns, vars, live, jumps)
}

// lookupVariable retrieves the VariableSpec for the given load instruction from
// the provided vars. If there's no VariableSpec for the given map and offset,
// it returns nil.
//
// A lookup failure doesn't mean there's a bug in our code or in the BPF
// program. ebpf-go only emits VariableSpecs for symbols with global visibility,
// so function-scoped variables and many other symbols in .bss may not have an
// associated VariableSpec.
func lookupVariable(load *asm.Instruction, vars map[mapOffset]VariableSpec) VariableSpec {
	mo := mapOffset{
		mapName: unique.Make(load.Reference()),
		offset:  uint64(load.Constant >> 32),
	}

	vs, found := vars[mo]
	if !found {
		return nil
	}
	return vs
}

// evalBranch evaluates the branch instruction based on the value of the
// variable it refers to.
//
// Returns true if the branch is always taken, false if it is never taken,
func evalBranch(branch *asm.Instruction, vs VariableSpec) (bool, error) {
	// Extract the variable value
	var (
		value int64
		err   error
	)
	switch vs.Size() {
	case 1:
		var value8 int8
		err = vs.Get(&value8)
		value = int64(value8)
	case 2:
		var value16 int16
		err = vs.Get(&value16)
		value = int64(value16)
	case 4:
		var value32 int32
		err = vs.Get(&value32)
		value = int64(value32)
	case 8:
		var value64 int64
		err = vs.Get(&value64)
		value = value64
	default:
		return false, fmt.Errorf("jump instruction on variable %v of size %d?", vs, vs.Size())
	}
	if err != nil {
		return false, fmt.Errorf("getting value of variable: %w", err)
	}

	// Now lets determine if the branch is always taken or never taken.
	var jump bool
	switch op := branch.OpCode.JumpOp(); op {
	case asm.JEq, asm.JNE:
		jump = value == branch.Constant
		if op == asm.JNE {
			jump = !jump
		}

	case asm.JGT, asm.JLE:
		jump = value > branch.Constant
		if op == asm.JLE {
			jump = !jump
		}

	case asm.JLT, asm.JGE:
		jump = value < branch.Constant
		if op == asm.JGE {
			jump = !jump
		}

	case asm.JSGT, asm.JSLE:
		jump = value > branch.Constant
		if op == asm.JSLE {
			jump = !jump
		}

	case asm.JSLT, asm.JSGE:
		jump = value < branch.Constant
		if op == asm.JSGE {
			jump = !jump
		}

	case asm.JSet:
		jump = value&branch.Constant != 0

	default:
		return false, fmt.Errorf("unsupported jump instruction: %v", branch)
	}

	return jump, nil
}
