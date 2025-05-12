// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unique"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// getUnusedMaps reads back the JIT-ed instructions for all programs in the collection
// and determines which of the maps in the collection are actually used by the JIT-ed
// programs and which are not.
//
// This logic is used to verify that our userspace dead code elimination
// is correct, and that we are not loading any maps that end up not being used after
// the kernel does its own dead code elimination.
func getUnusedMaps(coll *ebpf.Collection, knownUnused []string) (usedMaps []string, unusedMaps []string, err error) {
	// Create a index from map ID to map name for all maps in the collection.
	unusedMapsByID := make(map[ebpf.MapID]string)
	for name, m := range coll.Maps {
		minfo, err := m.Info()
		if err != nil {
			panic(err)
		}

		mid, bool := minfo.ID()
		if !bool {
			return nil, nil, fmt.Errorf("No map ID available for map %s", name)
		}

		if !slices.Contains(knownUnused, name) {
			unusedMapsByID[mid] = name
		}
	}

	// Go over all programs that were loaded, and remove any maps that are referenced
	for _, prog := range coll.Programs {
		progInfo, err := prog.Info()
		if err != nil {
			panic(err)
		}

		// Read back the xlated BPF instructions
		progInsns, err := progInfo.Instructions()
		if err != nil {
			panic(err)
		}

		// Loop over the instructions to find all maps that are referenced after dead code elimination.
		for _, insn := range progInsns {
			if insn.IsLoadFromMap() {
				// The map ID is stored in the constant field of the instruction
				id := ebpf.MapID(uint32(insn.Constant))
				name, found := unusedMapsByID[id]
				if found {
					usedMaps = append(usedMaps, name)
					delete(unusedMapsByID, id)
				}
			}
		}
	}

	// Return any remaining maps that are not referenced by any program after
	// being loaded into the kernel.
	return usedMaps, slices.Collect(maps.Values(unusedMapsByID)), nil
}

// doNotPruneTag must be kept in sync with __do_not_prune in bpf/include/bpf/section.h
const doNotPruneTag = "do-not-prune"

// removeUnusedMaps analyzes the collection spec to detect which branches of the code
// will be dead with the supplied variable values. It then removes any maps that are not
// used in any live code of any program in the collection spec.
func removeUnusedMaps(spec *ebpf.CollectionSpec) (neverPrune []string, err error) {
	mapsInUse := make(map[string]bool)

	// Even when the code does not reference a map with global data, cilium/ebpf
	// expects that these are present in the collection spec.
	for _, v := range spec.Variables {
		mapsInUse[v.MapName()] = true
		neverPrune = append(neverPrune, v.MapName())
	}

	// If the map is marked with the do-not-prune tag, we need to keep it.
	// Some maps such as global tail call maps we want to be created or loaded from a pin
	// so we can assign programs to them after loading. Even if the programs do not
	// reference the map.
	for mapName := range spec.Maps {
		var mapVar *btf.Var
		if err := spec.Types.TypeByName(mapName, &mapVar); err == nil {
			if slices.Contains(mapVar.Tags, doNotPruneTag) {
				mapsInUse[mapName] = true
				neverPrune = append(neverPrune, mapName)
			}
		}
	}

	// When populating a map-in-map with contents (other maps) defined at
	// compile time, we need to ensure the sub maps are not removed
	// since they will not be directly referenced in the code.
	for _, m := range spec.Maps {
		if m.Type != ebpf.ArrayOfMaps && m.Type != ebpf.HashOfMaps {
			continue
		}

		for _, c := range m.Contents {
			if subMapName, ok := c.Value.(string); ok {
				mapsInUse[subMapName] = true
				neverPrune = append(neverPrune, subMapName)
			}
		}
	}

	// Process programs in predictable order, which makes debugging easier.
	keys := slices.Sorted(maps.Keys(spec.Programs))
	for _, name := range keys {
		prog := spec.Programs[name]

		// Get the basic blocks for the given program.
		bbl := makeBlockList(prog.Instructions)

		// Remove any basic blocks from the list that are not reachable given
		// the current variable values.
		bbl = deadCodeElimination(
			bbl,
			ebpfVarSpecToVarSpec(spec.Variables),
		)

		// Record which maps are still referenced after dead code elimination.
		for _, block := range bbl {
			for _, inst := range block.insns {
				if inst.IsLoadFromMap() {
					mapsInUse[inst.Reference()] = true
				}
			}
		}
	}

	// The verifier will do a flat pass over all provided instructions to assert
	// that the file descriptors in any map pointer load instructions are valid.
	// Even if that instruction later turns out to be dead/unreachable.
	//
	// So loop over all instruction. If we find a map load instruction that
	// references a map that is not used (we concluded it is dead code).
	// We replace that instruction with a normal load immediate instruction
	// instead of one that references a map file descriptor.
	for _, prog := range spec.Programs {
		progInsns := prog.Instructions
		for idx, inst := range progInsns {
			if inst.IsLoadFromMap() {
				// Replace the load from map instruction with a LDIMM64 instruction that
				// does not reference a map file descriptor.
				//
				// If for whatever reason we made a mistake and the verifier attempts to use
				// this instruction, as map pointer, this value should be visible and recognizable
				// in the verifier log.
				const poisonedMapLoad = 0xbad3420
				if !mapsInUse[inst.Reference()] {
					prog.Instructions[idx] = asm.LoadImm(inst.Dst, poisonedMapLoad, asm.DWord)
				}
			}
		}
	}

	// Delete the map from the spec so cilium/ebpf does not create it (since it will create
	// all maps in the spec, even if they are not used).
	for name := range spec.Maps {
		if _, ok := mapsInUse[name]; !ok {
			delete(spec.Maps, name)
		}
	}

	return neverPrune, nil
}

// A basicBlock is a contiguous sequence of instructions that is executed
// together. Boundaries are defined by branching instructions.
type basicBlock struct {
	id       int
	startIdx int
	insns    asm.Instructions

	reachableFrom []*basicBlock
	branch        *basicBlock
	noBranch      *basicBlock
}

type blockList []*basicBlock

// Make the block list printable, which is useful for debugging.
func (blocks blockList) String() string {
	var sb strings.Builder
	for _, block := range blocks {
		sb.WriteString("===\n")
		sb.WriteString("Block ID: ")
		sb.WriteString(strconv.Itoa(block.id))
		sb.WriteString("\n")
		sb.WriteString("Reachable from: [")
		for i, from := range block.reachableFrom {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(strconv.Itoa(from.id))
		}
		sb.WriteString("]\n\n")
		for i, inst := range block.insns {
			sb.WriteString(strconv.Itoa(i + block.startIdx))
			sb.WriteString(": ")
			sb.WriteString(fmt.Sprint(inst))
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
		if block.branch != nil {
			sb.WriteString("Branch: ")
			sb.WriteString(strconv.Itoa(block.branch.id))
			sb.WriteString("\n")
		}
		if block.noBranch != nil {
			sb.WriteString("No Branch: ")
			sb.WriteString(strconv.Itoa(block.noBranch.id))
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// Copy creates a deep copy of the block list. Needed since
// we have a lot of inter-linked pointers.
func (blocks blockList) Copy() blockList {
	newList := make(blockList, len(blocks))
	blkByID := make(map[int]*basicBlock, len(blocks))

	// Copy all non-pointer fields first. Storing the id -> *BasicBlock mapping
	for i, block := range blocks {
		newList[i] = &basicBlock{
			id:       block.id,
			startIdx: block.startIdx,
			insns:    slices.Clone(block.insns),
		}
		blkByID[block.id] = newList[i]
	}

	// Now copy the pointer fields. Use the IDs which are the same to get pointers
	// to the new blocks.
	for i, block := range blocks {
		newList[i].reachableFrom = make([]*basicBlock, len(block.reachableFrom))
		for j, from := range block.reachableFrom {
			newList[i].reachableFrom[j] = blkByID[from.id]
		}
		if block.branch != nil {
			newList[i].branch = blkByID[block.branch.id]
		}
		if block.noBranch != nil {
			newList[i].noBranch = blkByID[block.noBranch.id]
		}
	}

	return newList
}

// makeBlockList performs basic block analysis on the given instructions.
// It returns a list of basic blocks, each block contains a list of instructions
// which always execute together (no branches and jump targets).
// The block list is in the same order as they appear in the instruction stream.
// Each block can point to 0, 1 or 2 blocks (end of program, branch target, no branch target).
// Each block also records all blocks that point to it, so we can follow the graph in
// both directions.
func makeBlockList(insns asm.Instructions) blockList {
	// Jump offsets are in units of [asm.InstructionSize], but some instructions
	// are 2x the size of a normal instruction (e.g. dword loads). So we cannot
	// use the index of an instruction and offsets interchangeably.
	// We need to create a mapping of instruction index to offset in the instruction
	// stream, and vice versa.
	offsetToIdx := make(map[int]int)
	idxToOffset := make(map[int]int)
	offset := 0
	for idx, inst := range insns {
		offsetToIdx[offset] = idx
		idxToOffset[idx] = offset
		offset += 1
		if inst.OpCode.IsDWordLoad() {
			offset += 1
		}
	}

	// Now lets create an index of all "edges" between basic blocks, and there
	// reverse counterparts.
	edges := make(map[int]int)
	reverseEdge := make(map[int]bool)
	for idx, inst := range insns {
		// Only jump instructions cause a branch to another block.
		if !inst.OpCode.Class().IsJump() {
			continue
		}

		// Execution ends at an exit instruction, so no branch occurs. And calls
		// do no cause a branch, execution continues after the call.
		if inst.OpCode.JumpOp() == asm.Exit || inst.OpCode.JumpOp() == asm.Call {
			continue
		}

		curOff, ok := idxToOffset[idx]
		if !ok {
			panic("Could not find offset for instruction")
		}

		// Jump target is the current offset + the instruction offset + 1
		targetOff := curOff + int(inst.Offset) + 1
		// Unless we have a jump32 + JA, which is a "long jump", offset is
		// encoded in the constant field.
		if inst.OpCode.Class() == asm.Jump32Class && inst.OpCode.JumpOp() == asm.Ja {
			targetOff = curOff + int(inst.Constant) + 1
		}

		targetIdx, ok := offsetToIdx[targetOff]
		if !ok {
			panic("Could not find instruction for offset")
		}

		edges[idx] = targetIdx
		reverseEdge[targetIdx] = true
	}

	// Create a list of basic blocks. The first block starts at 0
	blocks := make(map[int]*basicBlock, len(edges)+len(reverseEdge))
	blocks[0] = &basicBlock{
		startIdx: 0,
	}

	// Create a block for each edge or reverse edge.
	for idx := range insns {
		if _, isEdge := edges[idx]; isEdge {
			// If an edge starts at the current instruction, we create a new block
			// starting after the current instruction.
			// Unless there are no more instructions.
			if idx != len(insns)-1 {
				blocks[idx+1] = &basicBlock{
					startIdx: idx + 1,
				}
			}
		}

		// If the current instruction is the target of a branch, we create a new block
		// starting at the current instruction.
		if reverseEdge[idx] {
			blocks[idx] = &basicBlock{
				startIdx: idx,
			}
		}
	}

	// Now we need to fill in the blocks with instructions and link them together.
	var curBlock *basicBlock
	for idx, inst := range insns {
		// If the current instruction index is the start of a new block.
		if blk, ok := blocks[idx]; ok {
			// If there was a previous block, and its last instruction was not
			// a Exit or JumpAlways instruction, then its `noBranch` will be
			// the fallthrough to this next block.
			if curBlock != nil &&
				curBlock.insns[len(curBlock.insns)-1].OpCode.JumpOp() != asm.Exit &&
				curBlock.insns[len(curBlock.insns)-1].OpCode.JumpOp() != asm.Ja {
				curBlock.noBranch = blk
				blk.reachableFrom = append(blk.reachableFrom, curBlock)
			}

			curBlock = blk
		}

		curBlock.insns = append(curBlock.insns, inst)

		if inst.OpCode.Class().IsJump() {
			switch inst.OpCode.JumpOp() {
			case asm.Ja:
				// We reached a JumpAlways. Which is unconditional, so we only
				// set the `noBranch` to its jump target.
				target := blocks[edges[idx]]
				curBlock.noBranch = target
				target.reachableFrom = append(target.reachableFrom, curBlock)

			case asm.Exit, asm.Call:
				// not a branching instruction

			default:
				// For all other instructions, set the `branch` the the target.
				// The `noBranch` will be the fallthrough to the next instruction.
				target := blocks[edges[idx]]
				curBlock.branch = target
				target.reachableFrom = append(target.reachableFrom, curBlock)
			}
		}
	}

	// Collect our blocks from the map, and sort them so they are in execution order.
	blockList := slices.SortedFunc(maps.Values(blocks), func(a, b *basicBlock) int {
		return a.startIdx - b.startIdx
	})

	// Assign IDs, just the index in the list. These are useful to identify
	// which block get removed during dead code elimination.
	for i, block := range blockList {
		block.id = i
	}

	return blockList
}

// Make a variable spec interface that is satisfied by the ebpf.VariableSpec
// This makes testing easier since we can create a mock variable spec.
var _ VariableSpec = (*ebpf.VariableSpec)(nil)

type VariableSpec interface {
	MapName() string
	Offset() uint64
	Size() uint64
	Get(out any) error
}

func ebpfVarSpecToVarSpec(variables map[string]*ebpf.VariableSpec) map[string]VariableSpec {
	variablesMap := make(map[string]VariableSpec)
	for name, varSpec := range variables {
		variablesMap[name] = varSpec
	}
	return variablesMap
}

// deadCodeElimination finds "predictable branches", branching instructions that compare
// against a load time constant (via frozen rodata map aka variables).
// Given the value of these variables, we can determine if the branch will always or never
// be taken. The block list is then modified to reflect this, and any blocks that
// become unreachable are removed from the list.
func deadCodeElimination(blocks blockList, variables map[string]VariableSpec) blockList {
	// Variables in the collection spec are identified by name. However the
	// instructions will refer to them by their map name (symbol reference) and offset.
	// So we need to create a mapping of map name and offset to the variable spec.
	type mapOffset struct {
		mapName unique.Handle[string]
		offset  uint64
	}
	variablesMap := make(map[mapOffset]VariableSpec)
	for _, v := range variables {
		variablesMap[mapOffset{
			mapName: unique.Make(v.MapName()),
			offset:  v.Offset(),
		}] = v
	}

determinePredictableBranches:
	for _, block := range blocks {
		// For every block, we are looking for the following pattern:
		//   LoadMapValue dst: Rx, fd: 0 off: {offset of variable in global data value} <{name of global data map}>
		//   LdXMem{B,H,W,DW} dst: Ry src: Rx off: 0
		//   J{OP}IMM dst: Ry off:{jump offset} imm: {constant value}
		//
		// Which is what the bytecode looks like for:
		// if (CONFIG(enable_feature_a)) {
		// or
		// if (CONFIG(number_of_something) > 5) {

		// Only the last instruction of a block can be a branch instruction.
		// Get the last instruction.
		branchInst := block.insns[len(block.insns)-1]
		// Remember what block the branch instruction is in, since we will
		// might up modifying `block` when we follow an edge.
		branchBlock := block

		switch branchInst.OpCode.JumpOp() {
		case asm.Exit, asm.Call:
			// not a branching instruction
			continue
		case asm.Ja:
			// not a conditional jump
			continue
		case asm.InvalidJumpOp:
			// not a jump instruction
			continue
		}

		// Only consider jumps that check `dst` against a constant value.
		if branchInst.OpCode.Source() != asm.ImmSource {
			continue
		}

		// Walk backwards, try to find the variable dereference instruction.
		// Since all CONFIG variables are `volatile`, the compiler should
		// emit a dereference instruction for every branching instruction.
		//
		// We expect these to be in the same basic block. Even though its
		// common to see other instructions in between them.
		ldIdx := len(block.insns) - 2
		for {
			// If we reach the top of the block, and we have not found a load instruction,
			// we have not found a predictable branch, continue to the next block.
			if ldIdx < 0 {
				continue determinePredictableBranches
			}

			ld := block.insns[ldIdx]

			// Look for a memory load that populates the same register as the branch
			// instruction is comparing.
			if ld.OpCode.Class().IsLoad() &&
				ld.OpCode.Mode() == asm.MemMode ||
				ld.Dst == branchInst.Dst {

				// We found what we are looking for, break out of the loop.
				break
			}

			if ld.Dst == branchInst.Dst {
				// We did not find a load instruction, but we did find an instruction
				// that populates the same register as the branch instruction. So we can stop looking.
				continue determinePredictableBranches
			}

			ldIdx--
		}

		ld := block.insns[ldIdx]

		// Start at the instruction before the load instruction, and go backwards.
		// Even though the CONFIG variable is volatile, its still legal for the compiler
		// to reuse a register containing the map pointer. So we need to follow edges
		// to blocks that jump to this block if we don't find a map load in the current block.
		//
		// Note: the compiler should favor re-constructing the map pointer over spilling
		// to the stack, so we don't consider stack spilling.

		mapPtrIdx := ldIdx - 1
		visited := make(map[*basicBlock]bool)
		for {
			// If we iterated past the start of the block, and we have not found a
			// map load, then see if we can follow to a previous block.
			if mapPtrIdx < 0 {
				if len(block.reachableFrom) == 0 {
					// No more blocks to check, so we can stop.
					continue determinePredictableBranches
				}

				if len(block.reachableFrom) > 1 {
					// Multiple blocks branch to this one, that condition is currently
					// to complex to handle, and its currently not clear if this is even
					// something that would occur in practice.
					// We might reconsider implementing this in the future.
					continue determinePredictableBranches
				}

				// Prevent infinite loops in case of cycles.
				if visited[block.reachableFrom[0]] {
					// We have already visited this block, so we can stop.
					continue determinePredictableBranches
				}

				visited[block.reachableFrom[0]] = true
				block = block.reachableFrom[0]
				mapPtrIdx = len(block.insns) - 1
			}

			mapPtr := block.insns[mapPtrIdx]

			// The `mapPtr` instruction sets the register we are interested in
			if mapPtr.Dst == ld.Src {
				if mapPtr.IsLoadFromMap() {
					// We found a map load that populates the register that the load
					// instruction dereferences.
					break
				}

				// If the instruction is not a map load, then we can stop looking,
				// then we can stop looking.
				continue determinePredictableBranches
			}

			mapPtrIdx--
		}

		mapPtr := block.insns[mapPtrIdx]

		// We have found our pattern of 3 instructions. If the map name + offset
		// matches one of the variables in the collection spec, then its a predictable
		// branch.

		varSpec, found := variablesMap[mapOffset{
			mapName: unique.Make(mapPtr.Reference()),
			offset:  uint64(mapPtr.Constant >> 32),
		}]
		if !found {
			continue determinePredictableBranches
		}

		// Extract the variable value
		var (
			value int64
			err   error
		)
		switch varSpec.Size() {
		case 1:
			var value8 int8
			err = varSpec.Get(&value8)
			value = int64(value8)
		case 2:
			var value16 int16
			err = varSpec.Get(&value16)
			value = int64(value16)
		case 4:
			var value32 int32
			err = varSpec.Get(&value32)
			value = int64(value32)
		case 8:
			var value64 int64
			err = varSpec.Get(&value64)
			value = value64
		default:
			// We can only handle 1, 2, 4 and 8 byte values.
			// We cannot handle arrays/structs/unions.
			continue determinePredictableBranches
		}
		if err != nil {
			continue determinePredictableBranches
		}

		// Now lets determine if the branch is always taken or never taken.
		var result bool
		op := branchInst.OpCode.JumpOp()
		switch op {
		case asm.JEq, asm.JNE:
			result = value == branchInst.Constant
			if op == asm.JNE {
				result = !result
			}

		case asm.JGT, asm.JLE:
			result = uint64(value) > uint64(branchInst.Constant)
			if op == asm.JLE {
				result = !result
			}

		case asm.JLT, asm.JGE:
			result = uint64(value) < uint64(branchInst.Constant)
			if op == asm.JGE {
				result = !result
			}

		case asm.JSGT, asm.JSLE:
			result = value > branchInst.Constant
			if op == asm.JSLE {
				result = !result
			}

		case asm.JSLT, asm.JSGE:
			result = value < branchInst.Constant
			if op == asm.JSGE {
				result = !result
			}

		case asm.JSet:
			result = value&branchInst.Constant != 0

		case asm.Ja:
			// not conditional, not relevant
			panic("jump always instruction at this stage of dead code elimination")
		case asm.Exit, asm.Call:
			// not a branching instruction, not relevant
			panic("exit/call instruction at this stage of dead code elimination")
		default:
			panic(errors.New("Unsupported jump op: " + branchInst.OpCode.JumpOp().String()))
		}

		// Clear the `branch` or `noBranch` depending on the result, and remove the
		// reverse edge from the target that is no longer reachable.
		if result {
			i := slices.IndexFunc(branchBlock.noBranch.reachableFrom, func(b *basicBlock) bool {
				return b == branchBlock
			})
			branchBlock.noBranch.reachableFrom = slices.Delete(branchBlock.noBranch.reachableFrom, i, i+1)
			branchBlock.noBranch = nil
		} else {
			i := slices.IndexFunc(branchBlock.branch.reachableFrom, func(b *basicBlock) bool {
				return b == branchBlock
			})
			branchBlock.branch.reachableFrom = slices.Delete(branchBlock.branch.reachableFrom, i, i+1)
			branchBlock.branch = nil
		}
	}

	// The graph of blocks has now been modified to account for the predictable branches.
	// Last step is to remove any blocks that are no longer reachable, directly or indirectly.
	//
	// We loop until we get an iteration where no blocks are removed.
	for {
		change := false

		// For every block except the first one (which is the entry point of the program)
		for i := len(blocks) - 1; i >= 1; i-- {
			blk := blocks[i]
			if len(blk.reachableFrom) == 0 {
				// If the block is no longer reachable, we need to remove it from the list.
				if blk.branch != nil {
					blk.branch.reachableFrom = slices.DeleteFunc(blk.branch.reachableFrom, func(b *basicBlock) bool {
						return b == blk
					})
				}
				if blk.noBranch != nil {
					blk.noBranch.reachableFrom = slices.DeleteFunc(blk.noBranch.reachableFrom, func(b *basicBlock) bool {
						return b == blk
					})
				}
				blocks = slices.Delete(blocks, i, i+1)
				change = true
			}
		}

		if !change {
			break
		}
	}

	return blocks
}
