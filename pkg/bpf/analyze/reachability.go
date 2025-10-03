// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"strings"
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

type Reachable struct {
	blocks Blocks
	insns  asm.Instructions

	// l is a bitmap tracking reachable blocks.
	l Bitmap

	// j is a bitmap tracking predicted jumps. If the nth bit is 1, the jump
	// at the end of block n is predicted to always be taken.
	j Bitmap
}

func (r *Reachable) isLive(id uint64) bool {
	if id >= r.blocks.count() {
		return false
	}
	return r.l.Get(id)
}

func (r *Reachable) countAll() uint64 {
	return r.blocks.count()
}

func (r *Reachable) countLive() uint64 {
	return r.l.Popcount()
}

// Reachability determines whether or not each Block in blocks is reachable
// given the variables.
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
func Reachability(blocks Blocks, insns asm.Instructions, variables map[string]VariableSpec) (*Reachable, error) {
	if blocks == nil || blocks.count() == 0 {
		return nil, errors.New("nil or empty blocks")
	}

	if len(insns) == 0 {
		return nil, errors.New("nil or empty instructions")
	}

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

	r := &Reachable{
		blocks: blocks,
		insns:  insns,
		l:      NewBitmap(uint64(blocks.count())),
		j:      NewBitmap(uint64(blocks.count())),
	}

	// Start recursing at first block since it is always live.
	if err := r.visitBlock(blocks.first(), vars); err != nil {
		return nil, fmt.Errorf("predicting blocks: %w", err)
	}

	return r, nil
}

// Iterate returns an iterator that wraps an internal BlockIterator. The
// internal iterator is yielded along with a bool indicating whether the current
// instruction is reachable.
//
// The BlockIterator itself is yielded so it can be cloned to start a
// backtracking session.
func (r *Reachable) Iterate() iter.Seq2[*BlockIterator, bool] {
	return func(yield func(*BlockIterator, bool) bool) {
		iter := r.blocks.iterate(r.insns)
		for iter.Next() {
			live := r.l.Get(iter.block.id)
			if !yield(iter, live) {
				return
			}
		}
	}
}

func (r *Reachable) Dump(insns asm.Instructions) string {
	var sb strings.Builder
	for _, block := range r.blocks {
		sb.WriteString(fmt.Sprintf("\n=== Block %d ===\n", block.id))
		sb.WriteString(block.Dump(insns))

		sb.WriteString(fmt.Sprintf("Live: %t, ", r.l.Get(uint64(block.id))))
		sb.WriteString("branch: ")
		if r.j.Get(uint64(block.id)) {
			sb.WriteString("jump")
		} else {
			sb.WriteString("fallthrough")
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// findBranch backtracks exactly one instruction and checks if it's a branch
// instruction comparing a register against an immediate value. Returns
// the instruction if it met the criteria, nil otherwise.
func findBranch(iter *BlockIterator) *asm.Instruction {
	// Only the last instruction of a block can be a branch instruction.
	if !iter.Previous() {
		return nil
	}
	branch := iter.Instruction()

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

// findDereference backtracks instructions until it finds a memory load
// (dereference) into the given dst register.
//
// Since all CONFIG() variables are `volatile`, the compiler should emit a
// dereference before every branch instruction. These typically occur in the
// same basic block, albeit with a few unrelated instructions in between.
func findDereference(iter *BlockIterator, dst asm.Register) *asm.Instruction {
	for iter.Previous() {
		ins := iter.Instruction()
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

// findMapLoad backtracks instructions until it finds a map load instruction
// that populates the given src register.
//
// Even though CONFIG() variables are declared volatile, the compiler may still
// decide to reuse the register containing the map pointer for multiple
// dereferences. This often occurs in a predecessor block, so the pull function
// must support predecessor traversal.
//
// Note: the compiler should favor reconstructing the map pointer over spilling
// to the stack, so we don't consider stack spilling.
func findMapLoad(iter *BlockIterator, src asm.Register) *asm.Instruction {
	for iter.Previous() {
		ins := iter.Instruction()
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
func (r *Reachable) unpredictableBlock(b *Block, vars map[mapOffset]VariableSpec) error {
	if err := r.visitBlock(b.branch, vars); err != nil {
		return fmt.Errorf("visiting branch block %d: %w", b.branch.id, err)
	}
	if err := r.visitBlock(b.fthrough, vars); err != nil {
		return fmt.Errorf("visiting fallthrough block %d: %w", b.fthrough.id, err)
	}
	return nil
}

// visitBlock recursively visits a block and its successors to determine
// reachability based on the branch instructions and the provided vars.
func (r *Reachable) visitBlock(b *Block, vars map[mapOffset]VariableSpec) error {
	if b == nil {
		return nil
	}

	// Don't evaluate the same block twice, this would lead to an infinite loop.
	// A live block implies a visited block.
	if r.l.Get(b.id) {
		return nil
	}
	r.l.Set(b.id, true)

	iter := b.iterateGlobal(r.blocks, r.insns)

	branch := findBranch(iter)
	if branch == nil {
		return r.unpredictableBlock(b, vars)
	}

	deref := findDereference(iter, branch.Dst)
	if deref == nil {
		return r.unpredictableBlock(b, vars)
	}

	load := findMapLoad(iter, deref.Src)
	if load == nil {
		return r.unpredictableBlock(b, vars)
	}

	vs := lookupVariable(load, vars)
	if vs == nil || !vs.Constant() {
		return r.unpredictableBlock(b, vars)
	}

	jump, err := evalBranch(branch, vs, deref)
	if err != nil {
		return fmt.Errorf("evaluating branch of block %d: %w", b.id, err)
	}

	// If the branch is always taken, only visit the branch target.
	if jump {
		r.j.Set(b.id, true)
		return r.visitBlock(b.branch, vars)
	}

	// Otherwise, only visit the fallthrough target.
	return r.visitBlock(b.fthrough, vars)
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
func evalBranch(branch *asm.Instruction, vs VariableSpec, deref *asm.Instruction) (bool, error) {
	// Extract the field being accessed
	fieldSize := deref.OpCode.Size().Sizeof()
	fieldOffset := deref.Offset

	// Get the raw bytes of the variable
	rawBytes := make([]byte, vs.Size())
	if err := vs.Get(&rawBytes); err != nil {
		return false, fmt.Errorf("getting raw bytes of variable: %w", err)
	}

	// Validate field access bounds
	if int(fieldOffset)+fieldSize > len(rawBytes) {
		return false, fmt.Errorf("field access out of bounds")
	}

	// Extract the field value at the specified offset
	fieldBytes := rawBytes[fieldOffset : fieldOffset+int16(fieldSize)]
	var value int64
	switch fieldSize {
	case 1:
		value = int64(int8(fieldBytes[0]))
	case 2:
		value = int64(int16(binary.NativeEndian.Uint16(fieldBytes)))
	case 4:
		value = int64(int32(binary.NativeEndian.Uint32(fieldBytes)))
	case 8:
		value = int64(binary.NativeEndian.Uint64(fieldBytes))
	default:
		return false, fmt.Errorf("unsupported field size %d", fieldSize)
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
