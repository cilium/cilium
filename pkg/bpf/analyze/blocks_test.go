// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func branchingProg(tb testing.TB, n int) asm.Instructions {
	tb.Helper()

	// A program that ends up being cut into n blocks.
	orig := make(asm.Instructions, 0, n)
	for i := range n - 1 {
		ins := asm.JEq.Imm(asm.R0, int32(i), "")
		ins.Offset = 0
		orig = append(orig, ins)
	}
	orig[0] = orig[0].WithSymbol("prog")
	orig = append(orig, asm.Return())

	return orig
}

func callingProg(tb testing.TB, n int) asm.Instructions {
	tb.Helper()

	// Each function call results in a new block.
	// Exit is in its own block at the end of the program.
	// Each function gets a block as well.
	orig := make(asm.Instructions, 0, (n*3)+1)
	for i := range n {
		orig = append(orig, asm.Call.Label(fmt.Sprintf("fn%d", i)))
	}
	orig[0] = orig[0].WithSymbol("prog")
	orig = append(orig, asm.Return())

	for i := range n {
		fn := []asm.Instruction{
			asm.Mov.Imm(asm.R0, int32(i)).WithSymbol(fmt.Sprintf("fn%d", i)),
			asm.Return(),
		}
		orig = append(orig, fn...)
	}

	return orig
}

func TestMakeBlocksSimple(t *testing.T) {
	// A valid program with no branches.
	insns := asm.Instructions{
		asm.Mov.Imm32(asm.R0, 0).WithSymbol("prog"),
		asm.Return(),
	}

	b, err := MakeBlocks(insns)
	require.NoError(t, err)

	assert.EqualValues(t, 1, b.count())

	block := b.first()
	assert.EqualValues(t, 0, block.id)
	assert.Equal(t, 0, block.start)
	assert.Equal(t, 1, block.end)
	assert.Empty(t, block.predecessors)
	assert.Nil(t, block.branch)
	assert.Nil(t, block.fthrough)

	b2, err := MakeBlocks(insns)
	require.NoError(t, err)
	assert.Equal(t, b, b2)
}

func TestBlocksMultiplePredecessors(t *testing.T) {
	// A program with multiple predecessors to the last block.
	insns := asm.Instructions{
		asm.Mov.Imm32(asm.R0, 1).WithSymbol("prog"),
		asm.JEq.Imm(asm.R0, 0, "target"),
		asm.Mov.Imm32(asm.R1, 1),
		asm.JEq.Imm(asm.R1, 0, "target"),
		asm.Mov.Imm32(asm.R0, 0).WithSymbol("target"),
		asm.Return(),
	}

	// Marshal instructions to fix up references.
	require.NoError(t, insns.Marshal(io.Discard, binary.LittleEndian))

	blocks, err := MakeBlocks(insns)
	require.NoError(t, err)

	require.EqualValues(t, 3, blocks.count())

	last := blocks[2]
	assert.EqualValues(t, 2, last.id)
	assert.Len(t, last.predecessors, 2)
	assert.Contains(t, last.predecessors, blocks[0])
	assert.Contains(t, last.predecessors, blocks[1])
	assert.Equal(t, 4, last.start)
	assert.Equal(t, 5, last.end)
	assert.Nil(t, last.branch)
	assert.Nil(t, last.fthrough)

	// Pull instructions from the last block and make sure it doesn't continue
	// past the start of the block since it has multiple predecessors.
	bt := last.backtrack(insns)

	require.True(t, bt.Previous())
	assert.Equal(t, bt.Instruction(), &insns[5])

	require.True(t, bt.Previous())
	assert.Equal(t, bt.Instruction(), &insns[4])

	require.False(t, bt.Previous())
}

func TestMakeBlocksManyBranches(t *testing.T) {
	insns := branchingProg(t, 1000)

	b, err := MakeBlocks(insns)
	require.NoError(t, err)

	assert.EqualValues(t, 1000, b.count())

	b2, err := MakeBlocks(insns)
	require.NoError(t, err)
	assert.Equal(t, b, b2)
}

func TestMakeBlocksCalls(t *testing.T) {
	// A valid program with calls.
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0).WithSymbol("prog"),
		asm.Call.Label("fn"),
		asm.Return(),
		asm.Mov.Imm32(asm.R0, 0).WithSymbol("fn"),
		asm.Return(),
	}

	b, err := MakeBlocks(insns)
	require.NoError(t, err)

	require.Len(t, b, 2)

	blk := b.first()
	assert.Empty(t, blk.predecessors)
	assert.Nil(t, blk.fthrough)
	assert.Nil(t, blk.branch)
	assert.Equal(t, 0, blk.start)
	assert.Equal(t, 2, blk.end)

	blk = b[1]
	assert.Empty(t, blk.predecessors)
	assert.Nil(t, blk.fthrough)
	assert.Nil(t, blk.branch)
	assert.Equal(t, 3, blk.start)
	assert.Equal(t, 4, blk.end)

	b2, err := MakeBlocks(insns)
	require.NoError(t, err)
	assert.Equal(t, b, b2)
}

func TestMakeBlocksManyCalls(t *testing.T) {
	insns := callingProg(t, 100)

	b, err := MakeBlocks(insns)
	require.NoError(t, err)
	require.Len(t, b, 101)

	b2, err := MakeBlocks(insns)
	require.NoError(t, err)
	assert.Equal(t, b, b2)
}

func TestBlocksIterateLocal(t *testing.T) {
	insns := branchingProg(t, 100)

	bl, err := MakeBlocks(insns)
	require.NoError(t, err)

	assert.EqualValues(t, 100, bl.count())

	iter := bl.first().iterateLocal(insns)

	// Iterate over the first block only. Next should return false after the first
	// block is done and stay at index 0.
	assert.True(t, iter.Next())
	assert.False(t, iter.Next())
	assert.Equal(t, 0, iter.index)
}

func TestBlocksIterateGlobal(t *testing.T) {
	insns := branchingProg(t, 100)

	bl, err := MakeBlocks(insns)
	require.NoError(t, err)

	assert.EqualValues(t, 100, bl.count())

	iter := bl.iterate(insns)
	i := 0
	for ; iter.Next(); i++ {
		if iter.ins.OpCode.JumpOp() == asm.Exit {
			continue
		}

		// The Constant fields of the branching instructions are set to their insn
		// index. Make sure the iterator index matches.
		assert.EqualValues(t, iter.index, iter.ins.Constant)
	}

	// We should have seen all instructions.
	assert.Equal(t, 100, i)
	assert.Equal(t, 99, iter.index)
}

func TestBlocksIterateOffset(t *testing.T) {
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0).WithSymbol("prog"),
		asm.LoadImm(asm.R0, 0xffffffff, asm.DWord),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.LoadImm(asm.R0, 0x11111111, asm.DWord),
		asm.Return().WithSymbol("exit"),
	}

	// Marshal instructions to fix up references.
	require.NoError(t, insns.Marshal(io.Discard, binary.LittleEndian))

	bl, err := MakeBlocks(insns)
	require.NoError(t, err)

	assert.EqualValues(t, 3, bl.count())

	iter := bl.iterate(insns)

	assert.True(t, iter.Next()) // Pull MovImm
	assert.Equal(t, 0, iter.index)
	assert.Equal(t, asm.RawInstructionOffset(0), iter.offset)

	assert.True(t, iter.Next()) // Pull LoadImm
	assert.Equal(t, 1, iter.index)
	assert.Equal(t, asm.RawInstructionOffset(1), iter.offset)

	assert.True(t, iter.Next()) // Pull JEq
	assert.Equal(t, 2, iter.index)
	assert.Equal(t, asm.RawInstructionOffset(3), iter.offset) // Advance 2 raw insns due to LoadImm

	assert.True(t, iter.Next()) // Pull LoadImm
	assert.Equal(t, 3, iter.index)
	assert.Equal(t, asm.RawInstructionOffset(4), iter.offset)

	assert.True(t, iter.Next()) // Pull Return
	assert.Equal(t, 4, iter.index)
	assert.Equal(t, asm.RawInstructionOffset(6), iter.offset) // Advance 2 raw insns due to LoadImm

	assert.False(t, iter.Next())
}

func TestBacktracker(t *testing.T) {
	insns := asm.Instructions{
		asm.Ja.Label("prog").WithSymbol("prog"),
	}

	b, err := MakeBlocks(insns)
	require.NoError(t, err)

	assert.NotEmpty(t, b)

	bt := b.first().backtrack(insns)

	// Make sure single-instruction blocks work as expected.
	// First call: true, 0.
	require.True(t, bt.Previous())
	assert.Equal(t, 0, bt.index)

	// Second call: false, 0.
	require.False(t, bt.Previous())
	assert.Equal(t, 0, bt.index)
}

func TestBlocksDump(t *testing.T) {
	insns := branchingProg(t, 100)

	b, err := MakeBlocks(insns)
	require.NoError(t, err)

	// Dump the blocks to a string and make sure it doesn't panic.
	dump := b.Dump(insns)

	assert.NotEmpty(t, dump)
}

func BenchmarkComputeBlocks(b *testing.B) {
	b.ReportAllocs()

	// Program with a 1000 branches resulting in 1000 blocks.
	orig := branchingProg(b, 1000)

	for b.Loop() {
		b.StopTimer()
		insns := slices.Clone(orig)
		b.StartTimer()

		if _, err := computeBlocks(insns); err != nil {
			b.Fatal("Error making block list:", err)
		}
	}
}

func BenchmarkComputeBlocksCalls(b *testing.B) {
	b.ReportAllocs()

	// Program with 500 calls to 500 functions, resulting in 1000 blocks (plus 1
	// for Exit).
	orig := callingProg(b, 500)

	for b.Loop() {
		b.StopTimer()
		insns := slices.Clone(orig)
		b.StartTimer()

		if _, err := computeBlocks(insns); err != nil {
			b.Fatal("Error making block list:", err)
		}
	}
}
