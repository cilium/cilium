// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/cilium/ebpf/asm"
)

// leaderKey is used to store the leader metadata in an instruction's metadata.
type leaderKey struct{}

// A leader is an instruction at the beginning of a basic block.
type leader struct {
	// predecessors are instructions in other blocks that are always executed
	// before this instruction.
	predecessors []*asm.Instruction

	// block is the block that this instruction is the start of.
	block *Block
}

// setLeaderMeta sets the leader metadata for an instruction. This metadata
// is used to mark the start of a basic block and to store information about
// the block and its predecessors.
func setLeaderMeta(ins *asm.Instruction, meta *leader) {
	ins.Metadata.Set(leaderKey{}, meta)
}

// getLeaderMeta retrieves the leader metadata for an instruction.
func getLeaderMeta(ins *asm.Instruction) *leader {
	val := ins.Metadata.Get(leaderKey{})
	meta, ok := val.(*leader)
	if !ok {
		return nil
	}
	return meta
}

// addPredecessors adds one or more predecessor instructions to the list of
// predecessors for the given instruction. If a predecessor is already in the
// list, it is not added again.
//
// This is used to track the control flow graph of the program, where each
// instruction can have multiple predecessors (i.e. it can be reached from
// multiple branches). Initializes the instruction's leader metadata if it does
// not exist yet.
func addPredecessors(ins *asm.Instruction, preds ...*asm.Instruction) {
	l := getLeaderMeta(ins)
	if l == nil {
		l = &leader{}
		setLeaderMeta(ins, l)
	}
	for _, pred := range preds {
		if pred == nil {
			continue
		}
		if !slices.Contains(l.predecessors, pred) {
			l.predecessors = append(l.predecessors, pred)
		}
	}
}

// edgeKey is used to store the edge metadata in an instruction's metadata.
type edgeKey struct{}

// edge is a metadata structure that is associated with an instruction marking
// the end of a basic block. It can have a branch target (the target of a jump
// instruction) and a fallthrough target (the next instruction in the
// instruction stream that is executed if the branch is not taken).
type edge struct {
	branch   *asm.Instruction
	fthrough *asm.Instruction

	block *Block
}

// setEdgeMeta sets the edge metadata for an instruction.
func setEdgeMeta(ins *asm.Instruction, meta *edge) {
	ins.Metadata.Set(edgeKey{}, meta)
}

// getEdgeMeta retrieves the edge metadata for an instruction.
func getEdgeMeta(ins *asm.Instruction) *edge {
	val := ins.Metadata.Get(edgeKey{})
	meta, ok := val.(*edge)
	if !ok {
		return nil
	}
	return meta
}

// setEdgeBranchTarget sets the branch target for an edge instruction. This is
// used to mark the target of a jump instruction that branches to another basic
// block.
func setEdgeBranchTarget(ins *asm.Instruction, target *asm.Instruction) {
	e := getEdgeMeta(ins)
	if e == nil {
		e = &edge{}
		setEdgeMeta(ins, e)
	}
	e.branch = target
}

// setEdgeFallthrough sets the fallthrough target for an edge instruction. This
// is used to mark the next instruction in the instruction stream that is
// executed if the branch is not taken, typically the instruction immediately
// following the branch instruction.
func setEdgeFallthrough(ins *asm.Instruction, target *asm.Instruction) {
	if ins == nil {
		return
	}
	e := getEdgeMeta(ins)
	if e == nil {
		e = &edge{}
		setEdgeMeta(ins, e)
	}
	e.fthrough = target
}

// setBranchTarget creates a two-way association between both the branch
// instruction and its target instruction, as well as the target instruction and
// its natural predecessor. prev may be nil if the branch target is the first
// instruction in the program.
//
// This process creates two edges and a leader, updating existing metadata if
// the instructions were already marked as leaders or edges.
func setBranchTarget(branch, target, prev *asm.Instruction) {
	// Associate the branch instruction with its target. The target becomes a
	// leader, the branch instruction becomes an edge.
	setEdgeBranchTarget(branch, target)

	// Create a reverse link from the branch target to both the branch (jump)
	// instructions and the target's predecessor.
	if canFallthrough(prev) {
		// Creating a leader implicitly means making the instruction before it an
		// edge with a fallthrough target. Associate the target with its predecessor.
		setEdgeFallthrough(prev, target)
		addPredecessors(target, branch, prev)
	} else {
		// If the instruction preceding the branch target cannot fall through (Ja,
		// Exit), don't register it as a predecessor.
		setEdgeFallthrough(prev, nil)
		addPredecessors(target, branch)
	}
}

// A Block is a contiguous sequence of instructions that are executed together.
// Boundaries are defined by branching instructions.
//
// Blocks are attached to instructions via metadata and should not be modified
// after being created.
//
// It should never contain direct references to the original asm.Instructions
// since copying the ProgramSpec won't update pointers to the new copied insns.
// This is a problem when modifying instructions through
// [Blocks.LiveInstructions] after reachability analysis, since it would modify
// the original ProgramSpec's instructions.
type Block struct {
	id         uint64
	raw        asm.RawInstructionOffset
	start, end int

	predecessors []*Block
	branch       *Block
	fthrough     *Block
}

func (b *Block) leader(insns asm.Instructions) *leader {
	if len(insns) == 0 {
		return nil
	}
	return getLeaderMeta(&insns[b.start])
}

func (b *Block) edge(insns asm.Instructions) *edge {
	if len(insns) == 0 {
		return nil
	}

	if b.end >= len(insns) {
		return nil
	}

	return getEdgeMeta(&insns[b.end])
}

func (b *Block) len() int {
	return max(b.end-b.start+1, 0)
}

func (b *Block) iterate(insns asm.Instructions) *asm.InstructionIterator {
	if b.start < 0 || b.end < 0 || b.start >= len(insns) || b.end >= len(insns) {
		return nil
	}

	i := insns[b.start : b.end+1].Iterate()

	// Setting these fields correctly allows the insn printer to show correct
	// raw offsets of instructions matching verifier output. Makes debugging
	// significantly easier.
	i.Index = b.start
	i.Offset = b.raw

	return i
}

// backward returns an iterator that traverses the instructions in the block
// in reverse order, starting from the last instruction and going to the first.
//
// Doesn't return an [iter.Seq2] because converting it to a pull-based iterator
// using [iter.Pull] is incredibly, prohibitively expensive. Maybe this improves
// in a future Go version.
func (b *Block) backward(insns asm.Instructions) func() (*asm.Instruction, bool) {
	// Track depth of block traversal to avoid infinite loops. Used in favor of a
	// visited set since it's much cheaper than frequent map lookups. Typical
	// depth is 1-3 with some double-digit outliers.
	const maxDepth uint8 = 128
	var depth uint8 = 0

	i := b.len() - 1
	return func() (*asm.Instruction, bool) {
		if i < 0 {
			// If we've reached the start of the block, roll over to its predecessor
			// if there is exactly one. Sometimes, map pointers are reused from a
			// previous block.
			//
			// This is not needed for blocks with multiple predecessors, since
			// execution could've originated from any of them, making the contents of
			// the pointer register undefined.
			if len(b.predecessors) == 1 {
				pred := b.predecessors[0]
				if pred == b {
					// Blocks representing loops can have themselves as a predecessor.
					// Don't roll over to itself for obvious reasons.
					return nil, false
				}

				if depth >= maxDepth {
					return nil, false
				}
				depth++

				b = pred
				i = b.len() - 1
			} else {
				// Zero or multiple predecessors means we can't roll over to a
				// predecessor, stop here.
				return nil, false
			}
		}

		out := &insns[b.start+i]
		i--
		return out, true
	}
}

func (b *Block) String() string {
	return b.Dump(nil)
}

func (b *Block) Dump(insns asm.Instructions) string {
	var sb strings.Builder
	sb.WriteString("Predecessors: [")
	for i, from := range b.predecessors {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("%d", from.id))
	}
	sb.WriteString("]\n")
	sb.WriteString(fmt.Sprintf("Start: %d (raw %d), end: %d\n", b.start, b.raw, b.end))
	sb.WriteString("\n")

	if len(insns) != 0 {
		sb.WriteString("Instructions:\n")
		i := b.iterate(insns)
		for i.Next() {
			if i.Ins.Symbol() != "" {
				fmt.Fprintf(&sb, "\t%s:\n", i.Ins.Symbol())
			}
			if src := i.Ins.Source(); src != nil {
				line := strings.TrimSpace(src.String())
				if line != "" {
					fmt.Fprintf(&sb, "\t%*s; %s\n", 4, " ", line)
				}
			}
			fmt.Fprintf(&sb, "\t%*d: %v\n", 4, i.Offset, i.Ins)
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("Instructions: not provided, call Dump() with insns\n")
	}

	if b.branch != nil {
		sb.WriteString("Branch: ")
		sb.WriteString(fmt.Sprintf("%d", b.branch.id))
		sb.WriteString("\n")
	}

	if b.fthrough != nil {
		sb.WriteString("Fallthrough: ")
		sb.WriteString(fmt.Sprintf("%d", b.fthrough.id))
		sb.WriteString("\n")
	}

	return sb.String()
}

// getBlock retrieves the block associated with an instruction. It checks both
// the leader and edge metadata to find the block. If neither is found, it
// returns nil, indicating that the instruction forms neither the start nor end
// of a basic block.
func getBlock(ins *asm.Instruction) *Block {
	l := getLeaderMeta(ins)
	if l != nil {
		return l.block
	}

	e := getEdgeMeta(ins)
	if e != nil {
		return e.block
	}

	return nil
}

// Blocks is a list of basic blocks.
type Blocks struct {
	b []*Block

	// l is a bitmap tracking reachable blocks.
	l bitmap

	// j is a bitmap tracking predicted jumps. If the nth bit is 1, the jump
	// at the end of block n is predicted to always be taken.
	j bitmap
}

// LiveInstructions returns a sequence of [asm.Instruction]s held by Blocks. The
// bool value indicates if the instruction is live (reachable), false if it's
// not.
//
// Returns nil if block reachability hasn't been computed yet.
func (bl *Blocks) LiveInstructions(insns asm.Instructions) iter.Seq2[*asm.Instruction, bool] {
	if len(bl.l) == 0 {
		return nil
	}

	return func(yield func(*asm.Instruction, bool) bool) {
		for _, b := range bl.b {
			for i := range insns[b.start : b.end+1] {
				ins := &insns[b.start+i]
				live := bl.l.get(b.id)
				if !yield(ins, live) {
					return
				}
			}
		}
	}
}

func newBlocks(cap uint64) *Blocks {
	if cap == 0 {
		// Provide capacity for at least one block.
		cap = 1
	}

	return &Blocks{
		b: make([]*Block, 0, cap),
	}
}

func (bl *Blocks) count() uint64 {
	return uint64(len(bl.b))
}

func (bl *Blocks) add(b *Block) {
	if b == nil {
		return
	}

	b.id = uint64(bl.count())
	bl.b = append(bl.b, b)
}

func (bl *Blocks) first() *Block {
	if len(bl.b) == 0 {
		return nil
	}
	return bl.b[0]
}

func (bl *Blocks) last() *Block {
	if len(bl.b) == 0 {
		return nil
	}
	return bl.b[len(bl.b)-1]
}

func (bl *Blocks) isLive(id uint64) bool {
	if id >= bl.count() {
		return false
	}
	return bl.l.get(id)
}

func (bl *Blocks) countLive() uint64 {
	var count uint64
	for i := range uint64(len(bl.b)) {
		if bl.l.get(i) {
			count++
		}
	}
	return count
}

func (bl *Blocks) String() string {
	return bl.Dump(nil)
}

func (bl *Blocks) Dump(insns asm.Instructions) string {
	var sb strings.Builder
	for _, block := range bl.b {
		sb.WriteString(fmt.Sprintf("\n=== Block %d ===\n", block.id))
		sb.WriteString(block.Dump(insns))

		// No reachability information yet.
		if len(bl.l) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("Live: %t, ", bl.l.get(uint64(block.id))))
		sb.WriteString("branch: ")
		if bl.j.get(uint64(block.id)) {
			sb.WriteString("jump")
		} else {
			sb.WriteString("fallthrough")
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// Copy returns a shallow copy of the block list. Reachability information is
// not copied.
//
// Individual blocks are attached to leader and edge [asm.Instruction] metadata
// and should not be modified.
func (bl *Blocks) Copy() *Blocks {
	return &Blocks{
		b: slices.Clone(bl.b),
	}
}

// MakeBlocks returns a list of basic blocks of instructions that are always
// executed together. Multiple calls on the same insns will return the same
// Blocks object.
//
// Blocks are created by finding branches and jump targets in the given insns
// and cutting up the instruction stream accordingly.
func MakeBlocks(insns asm.Instructions) (*Blocks, error) {
	if len(insns) == 0 {
		return nil, errors.New("insns is empty, cannot compute blocks")
	}

	if blocks := loadBlocks(insns); blocks != nil {
		return blocks, nil
	}

	blocks, err := computeBlocks(insns)
	if err != nil {
		return nil, fmt.Errorf("computing blocks: %w", err)
	}

	if err := storeBlocks(insns, blocks); err != nil {
		return nil, fmt.Errorf("storing blocks: %w", err)
	}

	return blocks, nil
}

// computeBlocks computes the basic blocks from the given instruction stream.
func computeBlocks(insns asm.Instructions) (*Blocks, error) {
	targets, err := rawJumpTargets(insns)
	if err != nil {
		return nil, fmt.Errorf("collecting jump targets: %w", err)
	}

	if err := tagLeadersAndEdges(insns, targets); err != nil {
		return nil, fmt.Errorf("tagging instructions: %w", err)
	}

	blocks, err := allocateBlocks(insns)
	if err != nil {
		return nil, fmt.Errorf("allocating blocks: %w", err)
	}

	if err := connectBlocks(blocks, insns); err != nil {
		return nil, fmt.Errorf("connecting blocks: %w", err)
	}

	return blocks, nil
}

// blocksKey is used to store Blocks in an instruction's metadata.
type blocksKey struct{}

// storeBlocks associates the given Blocks with the first instruction in the
// given insns.
//
// If insns is empty, does nothing.
func storeBlocks(insns asm.Instructions, bl *Blocks) error {
	if len(insns) == 0 {
		return errors.New("insns is empty, cannot store Blocks")
	}

	insns[0].Metadata.Set(blocksKey{}, bl)

	return nil
}

// loadBlocks retrieves the Blocks associated with the first instruction in the
// given insns.
//
// If no Blocks is present, returns nil.
func loadBlocks(insns asm.Instructions) *Blocks {
	if len(insns) == 0 {
		return nil
	}

	blocks, ok := insns[0].Metadata.Get(blocksKey{}).(*Blocks)
	if !ok {
		return nil
	}

	return blocks
}

// rawJumpTargets returns a map of raw instruction offsets to jump targets,
// where each target is a logical instruction in the instruction stream.
//
// The raw instruction offsets are the offsets of the instructions in the raw
// bytecode, which may not correspond to the logical instruction indices due to
// variable instruction sizes (e.g. dword loads).
func rawJumpTargets(insns asm.Instructions) (rawTargets, error) {
	// Jump offsets are in raw instructions of size [asm.InstructionSize], but
	// some instructions are 2x the size of a normal instruction (e.g. dword
	// loads). Find the raw offsets of all jump targets and mark them for
	// resolution.
	targets := make(rawTargets)
	i := insns.Iterate()
	for i.Next() {
		target, ok := jumpTarget(i.Offset, i.Ins)
		if !ok {
			continue
		}

		// Queue the target as a 'raw' leader to be resolved to a logical insn in
		// the next loop.
		targets.add(target)

		// Mark the instruction as an incomplete edge to avoid re-checking if each
		// insn is a jump in a subsequent step.
		setEdgeMeta(i.Ins, &edge{})
	}

	if len(targets) == 0 {
		// No jump targets to resolve.
		return nil, nil
	}

	// Second loop for finding the [asm.Instruction] for each raw offset
	// identified in the previous step.
	next, stop := iter.Pull(targets.keysSorted())
	defer stop()

	// Memoize the next leader so we don't need a map lookup for every insn.
	nextTarget, ok := next()
	if !ok {
		return nil, errors.New("no jump target to resolve, this is a bug")
	}

	i = insns.Iterate()
	for i.Next() {
		if i.Offset != nextTarget {
			continue
		}

		// Map the raw instruction offset to its logical instruction.
		targets.resolve(i.Offset, i.Index, i.Ins)

		// Pull the next target to resolve.
		nextTarget, ok = next()
		if !ok {
			// No more targets to resolve.
			break
		}
	}

	return targets, nil
}

// tagLeadersAndEdges tags the instructions in the given instruction stream
// as leaders and/or edges based on their control flow properties. It identifies
// the first instruction as a leader without predecessors, the last instruction
// as an edge without a branch or fallthrough, and processes jump instructions
// to create leaders for their targets and edges for their predecessors.
//
// Returns error if any edge instruction does not have a target instruction at
// the specified raw offset.
func tagLeadersAndEdges(insns asm.Instructions, targets rawTargets) error {
	// Mark first insn as leader without predecessors, last insn as an edge
	// without a branch or fallthrough.
	setLeaderMeta(&insns[0], &leader{})
	setEdgeMeta(&insns[len(insns)-1], &edge{})

	if len(targets) == 0 {
		// No jump targets to resolve.
		return nil
	}

	// Find all jump instructions, create leaders for their targets and edges for
	// their predecessors.
	i := insns.Iterate()
	for i.Next() {
		// If the insn was identified as an edge in a prior step, add it as a
		// predecessor to the next instruction and to the branch target.
		e := getEdgeMeta(i.Ins)
		if e == nil {
			continue
		}

		// If the instruction is a branch, we need to find the target instruction
		// and set it as the branch target.
		raw, ok := jumpTarget(i.Offset, i.Ins)
		if !ok {
			// Edge doesn't have a jump target. This could be an exit or call
			// instruction, in which case there's no jump target to resolve and no
			// leader to create.
			continue
		}

		tgt := targets.get(raw)
		if tgt == nil {
			return fmt.Errorf("edge %v has no target instruction at offset %d", i.Ins, raw)
		}

		// In case of a jump to the first instruction, the target has no
		// predecessor, so we need a bounds check.
		var prev *asm.Instruction
		if tgt.index-1 >= 0 {
			prev = &insns[tgt.index-1]
		}
		setBranchTarget(i.Ins, tgt.ins, prev)

		// No next instruction, don't set a fallthrough target.
		if i.Index == len(insns)-1 {
			continue
		}

		// If the instruction is an unconditional jump, don't consider the next
		// instruction a fallthrough target.
		if i.Ins.OpCode.JumpOp() == asm.Ja {
			continue
		}

		next := &insns[i.Index+1]
		addPredecessors(next, i.Ins)
		setEdgeFallthrough(i.Ins, next)
	}

	return nil
}

// allocateBlocks returns a list of blocks based on leaders and edges identified
// in prior stages. It creates a new block whenever it encounters a leader
// instruction and finalizes the current one when it reaches an edge
// instruction. No blocks are pointing to each other yet, this is done in a
// subsequent step.
func allocateBlocks(insns asm.Instructions) (*Blocks, error) {
	blocks := newBlocks(0)

	var block *Block
	i := insns.Iterate()
	for i.Next() {
		// Roll over to the next block if this is a leader.
		if nextBlock := maybeAllocateBlock(i); nextBlock != nil {
			block = nextBlock
			blocks.add(block)
		}

		// Finalize the block if we've reached an edge.
		maybeFinalizeBlock(block, i)
	}

	if blocks.count() == 0 {
		return nil, errors.New("no blocks created, this is a bug")
	}

	return blocks, nil
}

// maybeAllocateBlock allocates a new block for the instruction pointed to by
// the iterator if it is a leader instruction. If the instruction is not a
// leader, it returns nil. This is used to start a new basic block when
// encountering a leader instruction in the instruction stream.
func maybeAllocateBlock(i *asm.InstructionIterator) *Block {
	l := getLeaderMeta(i.Ins)
	if l == nil {
		return nil
	}
	l.block = &Block{
		start: i.Index,
		raw:   i.Offset,
	}
	return l.block
}

// maybeFinalizeBlock finalizes the current block by populating its insns field
// and associating it with the edge metadata if the instruction is an edge.
// If the instruction is not an edge or the given block is nil, it does nothing.
func maybeFinalizeBlock(blk *Block, i *asm.InstructionIterator) {
	e := getEdgeMeta(i.Ins)
	if e == nil {
		return
	}
	if blk == nil {
		return
	}
	blk.end = i.Index
	e.block = blk
}

// connectBlocks connects the blocks in the given block list by setting their
// predecessors, branch and fallthrough targets based on the relationships
// between instructions identified in prior steps. Assumes that blocks have been
// allocated and that the leaders and edges have been tagged.
func connectBlocks(blocks *Blocks, insns asm.Instructions) error {
	if blocks.count() == 0 {
		return errors.New("no blocks to connect, this is a bug")
	}

	// Wire all blocks together by setting their predecessors, branch and
	// fallthrough targets.
	for _, blk := range blocks.b {
		// Predecessors of the first instruction are the block's predecessors.
		leader := blk.leader(insns)
		if leader == nil {
			return fmt.Errorf("block %d has no leader", blk.id)
		}

		blk.predecessors = make([]*Block, 0, len(leader.predecessors))
		for _, pi := range leader.predecessors {
			b := getBlock(pi)
			if b == nil {
				return fmt.Errorf("predecessor instruction %v has no block", pi)
			}
			blk.predecessors = append(blk.predecessors, b)
		}

		// Branch/fthrough targets of the last instruction are the block's branch
		// and fallthrough targets.
		edge := blk.edge(insns)
		if edge == nil {
			return fmt.Errorf("block %d has no edge", blk.id)
		}

		if edge.branch != nil {
			// If the edge has a branch target, set it as the block's branch target.
			b := getBlock(edge.branch)
			if b == nil {
				return fmt.Errorf("branch target %v has no block", edge.branch)
			}
			blk.branch = b
		}

		if edge.fthrough != nil {
			// If the edge has a fallthrough target, set it as the block's fallthrough
			// target.
			b := getBlock(edge.fthrough)
			if b == nil {
				return fmt.Errorf("fallthrough target %v has no block", edge.fthrough)
			}
			blk.fthrough = b
		}
	}

	return nil
}
