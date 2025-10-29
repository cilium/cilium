// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"encoding/binary"
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
	orig = append(orig, asm.Return())

	return orig
}

func TestMakeBlocksSimple(t *testing.T) {
	// A valid program with no branches.
	insns := asm.Instructions{
		asm.Mov.Imm32(asm.R0, 0),
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

func TestMakeBlocksManyBranches(t *testing.T) {
	insns := branchingProg(t, 1000)

	b, err := MakeBlocks(insns)
	require.NoError(t, err)

	assert.EqualValues(t, 1000, b.count())

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
		asm.Mov.Imm(asm.R0, 0),
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
