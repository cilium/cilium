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
	for range n - 1 {
		ins := asm.JEq.Imm(asm.R0, 0, "")
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
	assert.Nil(t, b.LiveInstructions(insns))

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
		asm.Mov.Imm32(asm.R0, 1),
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

	assert.EqualValues(t, 3, blocks.count())

	first := blocks.first()
	assert.EqualValues(t, 0, first.id)
	assert.Empty(t, first.predecessors)
	assert.Equal(t, 0, first.start)
	assert.Equal(t, 1, first.end)
	assert.Equal(t, blocks.b[2], first.branch)
	assert.Equal(t, blocks.b[1], first.fthrough)

	second := blocks.b[1]
	assert.EqualValues(t, 1, second.id)
	assert.Len(t, second.predecessors, 1)
	assert.Equal(t, first, second.predecessors[0])
	assert.Equal(t, 2, second.start)
	assert.Equal(t, 3, second.end)
	assert.Equal(t, blocks.b[2], second.branch)
	assert.Equal(t, blocks.b[2], second.fthrough)

	last := blocks.last()
	assert.EqualValues(t, 2, last.id)
	assert.Len(t, last.predecessors, 2)
	assert.Equal(t, first, last.predecessors[0])
	assert.Equal(t, second, last.predecessors[1])
	assert.Equal(t, 4, last.start)
	assert.Equal(t, 5, last.end)
	assert.Nil(t, last.branch)
	assert.Nil(t, last.fthrough)

	// Pull instructions from the last block and make sure it doesn't continue
	// past the start of the block since it has multiple predecessors.
	pull := last.backward(insns)
	ins, ok := pull()
	require.True(t, ok)
	assert.Equal(t, ins, &insns[5])

	ins, ok = pull()
	require.True(t, ok)
	assert.Equal(t, ins, &insns[4])

	_, ok = pull()
	require.False(t, ok)
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
