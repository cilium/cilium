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
func Reachability(blocks Blocks, insns asm.Instructions, variables map[string]*ebpf.VariableSpec) (*Reachable, error) {
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
	vars := make(map[mapOffset]*ebpf.VariableSpec)
	for _, v := range variables {
		vars[mapOffset{
			mapName: unique.Make(v.SectionName),
			offset:  v.Offset,
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

// isBranch checks if ins is a branch instruction comparing a register against
// an immediate value or another register. Returns the instruction if it met the
// criteria, nil otherwise.
func isBranch(branch *asm.Instruction) bool {
	if branch == nil {
		return false
	}

	switch branch.OpCode.JumpOp() {
	case asm.Exit, asm.Call, asm.Ja, asm.InvalidJumpOp:
		return false
	}

	return true
}

// findDereference backtracks instructions until it finds a memory load
// (dereference) into the given dst register.
//
// The returned int64 is the accumulated mask from any AND operations applied
// to the register after dereference. Mask value 0 means no mask was applied.
// Mask is currently limited to 32 bits.
//
// The bool return value indicates whether the dereferenced value needs to be
// sign-extended before being given to the branch resolver.
func findDereference(bt *Backtracker, dst asm.Register) (*asm.Instruction, int64, bool) {
	var extend bool
	var mask int64

	for bt.Previous() {
		ins := bt.Instruction()
		if ins.Dst != dst {
			continue
		}

		// Accumulate AND masks occurring after the dereference.
		//
		// ALU32 example:
		// 	54: LdXMemW dst: r1 src: r1 off: 0 imm: 0
		// 	55: AndImm32 dst: r1 imm: 1
		// 	56: JEq32Imm dst: r1 off: 1 imm: 0
		//
		// Ignore ALU32 vs ALU differences since:
		// - bitwise ops are signedness-agnostic
		// - mask value doesn't get sign-extended
		// - resulting value can never have more bits set than the original
		//
		// Limit mask value to 32 bits (imm) since 64-bit support would require more
		// backtracking to resolve the src register.
		if ins.OpCode.ALUOp() == asm.And {
			if ins.OpCode.Mode() == asm.MemMode {
				// Reg-reg AND not supported yet.
				break
			}

			mask |= ins.Constant
			continue
		}

		// Deal with left shifts and right shifts, which are emitted after
		// dereferencing signed integers to extend them to 64 bits.
		//
		// Example of a signed 16-bit dereference on ISAv1+:
		// 	29: LdXMemW dst: r1 src: r1 off: 0 imm: 0
		// 	30: LShImm dst: r1 imm: 48
		// 	31: ArShImm dst: r1 imm: 48
		// 	32: JSGTImm dst: r1 off: 1 imm: -1
		//
		// Example of a signed 8-bit dereference on ISAv3+:
		// 	29: LdXMemB dst: r1 src: r1 off: 0 imm: 0
		// 	30: LShImm32 dst: r1 imm: 24
		// 	31: ArShImm32 dst: r1 imm: 24
		// 	32: JSGT32Imm dst: r1 off: 1 imm: -1
		//
		// We need to extract a signal that sign-extension is needed, so we only
		// check if the second shift is arithmetic and whether their values match.
		// The branch resolver operates on int64 values, so extend to 64 bits
		// regardless of the original deref size. ALU32 presence is handled in the
		// resolver.
		if ins.OpCode.ALUOp() == asm.ArSh {
			shift := ins.Constant
			if !bt.Previous() {
				break
			}

			ins = bt.Instruction()
			if ins.Dst != dst {
				break
			}

			if ins.OpCode.ALUOp() == asm.LSh && ins.Constant == shift {
				extend = true
				continue
			}

			break
		}

		op := ins.OpCode
		if op.Class().IsLoad() && op.Mode() == asm.MemMode {
			return ins, mask, extend
		}

		// Register got clobbered, stop looking.
		break
	}

	return nil, 0, false
}

// findMapLoad backtracks instructions until it finds a map load instruction
// that populates the given src register.
func findMapLoad(bt *Backtracker, dst asm.Register) *asm.Instruction {
	for bt.Previous() {
		ins := bt.Instruction()
		if ins.Dst != dst {
			continue
		}

		if ins.IsLoadFromMap() {
			return ins
		}

		// Register got clobbered, stop looking.
		return nil
	}

	return nil
}

// findImmLoad backtracks instructions until it finds an immediate load into
// the given register.
//
// Detects both cBPF-style immediate loads as well as loads using the
// LdImm{B,H,W,DW} instructions.
func findImmLoad(bt *Backtracker, reg asm.Register) *asm.Instruction {
	for bt.Previous() {
		ins := bt.Instruction()
		if ins.Dst != reg {
			continue
		}

		if (ins.OpCode.Class().IsLoad() &&
			ins.OpCode.Mode() == asm.ImmMode) ||
			ins.IsConstantLoad(asm.DWord) {
			return ins
		}

		// Register got clobbered, stop looking.
		return nil
	}

	return nil
}

type mapOffset struct {
	mapName unique.Handle[string]
	offset  uint32
}

// unpredictableBlock is called when the branch cannot be predicted. It visits
// both the branch and fallthrough blocks.
func (r *Reachable) unpredictableBlock(b *Block, vars map[mapOffset]*ebpf.VariableSpec) error {
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
func (r *Reachable) visitBlock(b *Block, vars map[mapOffset]*ebpf.VariableSpec) error {
	if b == nil {
		return nil
	}

	// Don't evaluate the same block twice, this would lead to an infinite loop.
	// A live block implies a visited block.
	if r.l.Get(b.id) {
		return nil
	}
	r.l.Set(b.id, true)

	// Visit all bpf2bpf callees of this block since they are always reachable, as
	// references always appear before the block's final jump instruction.
	for _, callee := range b.calls {
		if err := r.visitBlock(callee, vars); err != nil {
			return fmt.Errorf("visiting callee %d: %w", callee.id, err)
		}
	}

	// Check if the last instruction is a branch we can predict. Don't allocate a
	// backtracker if the last instruction is not a branch.
	branch := b.last(r.insns)
	if !isBranch(branch) {
		return r.unpredictableBlock(b, vars)
	}

	// Start backtracking from the end of the block. Explicitly seek to the end of
	// the block so the next call to Previous() will yield the next-to-last insn
	// of the block.
	bt := b.backtrack(r.insns).Seek(b.end)
	jump, err := predictBranch(branch, bt, vars)
	if errors.Is(err, errUnpredictable) {
		return r.unpredictableBlock(b, vars)
	}
	if err != nil {
		return fmt.Errorf("predicting branch of block %d: %w", b.id, err)
	}

	// If the branch is always taken, only visit the branch target.
	if jump {
		r.j.Set(b.id, true)
		return r.visitBlock(b.branch, vars)
	}

	// Otherwise, only visit the fallthrough target.
	return r.visitBlock(b.fthrough, vars)
}

var errUnpredictable = errors.New("unpredictable branch")

// predictBranch attempts to predict the outcome of the given branch
// instruction.
//
// If the branch cannot be predicted, it returns [errUnpredictable]. If the
// returned bool is true, the branch is always taken. If false, the branch is
// never taken.
func predictBranch(branch *asm.Instruction, bt *Backtracker, vars map[mapOffset]*ebpf.VariableSpec) (bool, error) {
	switch branch.OpCode.Source() {
	// Immediate comparisons are limited to 32 bits since that's the size of the
	// imm field in a (double-wide) branch insn. In an imm comparison, the dst
	// field register contains the dereferenced value of the config variable.
	//
	// Example:
	//	0: LoadMapValue dst: r1, fd: 0 off: 4 <.rodata.config>
	//	2: LdXMemB dst: r2 src: r1 off: 0 imm: 0
	//	3: JNEImm dst: r2 off: 2 imm: 0
	case asm.ImmSource:
		dst, err := resolveRegister(bt, branch.Dst, vars)
		if errors.Is(err, errUnpredictable) {
			// Don't wrap err since this is a hot path.
			return false, err
		}
		if err != nil {
			return false, fmt.Errorf("resolving dst register %s: %w", branch.Dst, err)
		}

		jump, err := evalJumpOp(branch.OpCode, dst, branch.Constant)
		if err != nil {
			return false, fmt.Errorf("evaluating branch: %w", err)
		}

		return jump, nil

	// Register comparisons require finding both a map load and an immediate
	// load into the two registers used by the branch instruction.
	//
	// Example:
	//	0: LoadMapValue dst: r1, fd: 0 off: 4 <.rodata.config>
	//	2: LdXMemDW dst: r1 src: r1 off: 0 imm: 0
	//	3: LdImmDW dst: r2 imm: 42
	//	5: JGTReg dst: r1 src: r2 off: 2
	//
	// Note that src and reg may be swapped depending on the comparison op and the
	// compiler's mood. During initial testing, the config value was more often
	// found in dst.
	case asm.RegSource:
		dst, err := resolveRegister(bt.Clone(), branch.Dst, vars)
		if errors.Is(err, errUnpredictable) {
			return false, err
		}
		if err != nil {
			return false, fmt.Errorf("resolving dst register %s: %w", branch.Dst, err)
		}

		src, err := resolveRegister(bt, branch.Src, vars)
		if errors.Is(err, errUnpredictable) {
			return false, err
		}
		if err != nil {
			return false, fmt.Errorf("resolving src register %s: %w", branch.Src, err)
		}

		jump, err := evalJumpOp(branch.OpCode, dst, src)
		if err != nil {
			return false, fmt.Errorf("evaluating branch: %w", err)
		}

		return jump, nil

	default:
		return false, errUnpredictable
	}
}

// resolveRegister attempts to resolve the value of a given register by
// backtracking from the given iterator position.
//
// If the register is populated by a memory dereference, it backtracks further
// to find the map load and returns the value of the associated VariableSpec.
// If the register is populated by an immediate load, it returns the immediate
// value directly.
//
// Returns errUnpredictable if the register value cannot be resolved.
func resolveRegister(bt *Backtracker, reg asm.Register, vars map[mapOffset]*ebpf.VariableSpec) (int64, error) {
	// First, check if there's a dereference into the register.
	derefIter := bt.Clone()
	deref, mask, extend := findDereference(derefIter, reg)

	if deref != nil {
		// Found a dereference, continue looking for the map load.
		load := findMapLoad(derefIter, deref.Src)
		if load == nil {
			return 0, errUnpredictable
		}

		vs := lookupVariable(load, vars)
		if vs == nil || !vs.Constant() {
			return 0, errUnpredictable
		}

		v, err := loadVariable(vs, deref, extend)
		if err != nil {
			return 0, fmt.Errorf("loading variable value: %w", err)
		}

		// Bitwise operations on signed types are implementation-dependent in C due
		// to differences in signedness representations. [findDereference] only
		// recognizes AND operations occurring after lsh/arsh sequences, so apply
		// the mask after performing sign extension to respect the bytecode's order
		// of operations.
		//
		// For negative mask values, the correctness of the result will depend
		// completely on the width of the mask, so the programmer should take care
		// to size the mask appropriately. Note that mask values are currently
		// limited to 32 bits.
		if mask != 0 {
			v &= mask
		}

		return v, nil
	}

	// No dereference found, check for an immediate load.
	imm := findImmLoad(bt, reg)
	if imm == nil {
		return 0, errUnpredictable
	}

	return imm.Constant, nil
}

// derefSize returns the width in bytes of deref.
func derefSize(deref *asm.Instruction) (uint32, error) {
	// Make sure it's a dereference instruction.
	if !deref.OpCode.Class().IsLoad() || deref.OpCode.Mode() != asm.MemMode {
		return 0, fmt.Errorf("not a dereference instruction: %v", deref)
	}

	switch deref.OpCode.Size() {
	case asm.Byte:
		return 1, nil
	case asm.Half:
		return 2, nil
	case asm.Word:
		return 4, nil
	case asm.DWord:
		return 8, nil
	}

	return 0, fmt.Errorf("unsupported deref size: %v", deref.OpCode.Size())
}

// loadVariable loads n=(deref width) bytes from variable vs and returns it as
// an int64.
func loadVariable(vs *ebpf.VariableSpec, deref *asm.Instruction, extend bool) (int64, error) {
	size, err := derefSize(deref)
	if err != nil {
		return 0, fmt.Errorf("determining deref size: %w", err)
	}
	// Offset within the variable to load from.
	offset := uint32(deref.Offset)

	if vs.Size() < size+offset {
		return 0, fmt.Errorf("dereference past end of variable (var=%d, off=%d, deref=%d)", len(vs.Value), offset, size)
	}

	b := make([]byte, vs.Size())
	if err := vs.Get(b); err != nil {
		return 0, fmt.Errorf("getting VariableSpec value: %w", err)
	}

	b = b[offset : offset+size]

	switch size {
	case 1:
		if extend {
			return int64(int8(b[0])), nil
		}
		return int64(b[0]), nil
	case 2:
		if extend {
			return int64(int16(binary.NativeEndian.Uint16(b))), nil
		}
		return int64(binary.NativeEndian.Uint16(b)), nil
	case 4:
		if extend {
			return int64(int32(binary.NativeEndian.Uint32(b))), nil
		}
		return int64(binary.NativeEndian.Uint32(b)), nil
	case 8:
		return int64(binary.NativeEndian.Uint64(b)), nil
	}

	return 0, fmt.Errorf("unsupported size %d for variable load", size)
}

// s32Jump returns true if the given jump operation performs a signed 32-bit
// comparison.
func s32Jump(op asm.OpCode) bool {
	if op.Class() != asm.Jump32Class {
		return false
	}

	switch op.JumpOp() {
	case asm.JSGT, asm.JSGE, asm.JSLT, asm.JSLE:
		return true
	}

	return false
}

// evalJumpOp evaluates the jump operation op with the given dst and src
// operands. It returns true if the jump is taken, false otherwise.
func evalJumpOp(op asm.OpCode, dst, src int64) (bool, error) {
	// Sign-extend 32-bit comparisons in jumps to 64 bits. These instructions will
	// appear on machines supporting ISAv3 or later, where left-shift/right-shift
	// sequences are no longer used to sign-extend 32-bit operands, only for s16
	// and smaller. Apply the same treatment to both dst and src for consistency.
	if s32Jump(op) {
		dst = int64(int32(dst))
		src = int64(int32(src))
	}

	var jump bool
	switch op.JumpOp() {
	case asm.JEq:
		jump = dst == src

	case asm.JGT:
		jump = uint64(dst) > uint64(src)
	case asm.JGE:
		jump = uint64(dst) >= uint64(src)

	case asm.JSet:
		jump = dst&src != 0
	case asm.JNE:
		jump = dst != src

	case asm.JSGT:
		jump = dst > src
	case asm.JSGE:
		jump = dst >= src

	case asm.JLT:
		jump = uint64(dst) < uint64(src)
	case asm.JLE:
		jump = uint64(dst) <= uint64(src)
	case asm.JSLT:
		jump = dst < src
	case asm.JSLE:
		jump = dst <= src

	default:
		return false, fmt.Errorf("unsupported jump instruction: %v", op)
	}

	return jump, nil
}

// lookupVariable retrieves the VariableSpec for the given load instruction from
// the provided vars. If there's no VariableSpec for the given map and offset,
// it returns nil.
//
// A lookup failure doesn't mean there's a bug in our code or in the BPF
// program. ebpf-go only emits VariableSpecs for symbols with global visibility,
// so function-scoped variables and many other symbols in .bss may not have an
// associated VariableSpec.
func lookupVariable(load *asm.Instruction, vars map[mapOffset]*ebpf.VariableSpec) *ebpf.VariableSpec {
	mo := mapOffset{
		mapName: unique.Make(load.Reference()),
		offset:  uint32(load.Constant >> 32),
	}

	vs, found := vars[mo]
	if !found {
		return nil
	}
	return vs
}
