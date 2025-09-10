// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// Simple example with a `__config_use_map_b` Variable acting as a feature flag.
// When true, the code using `map_a` is unreachable and can be eliminated. When
// false, `map_a` is live must be kept. map_b is always live since it's the
// default value for map pointer variable.
func TestReachabilitySimple(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("../testdata/unused-map-pruning.o")
	require.NoError(t, err)

	obj := struct {
		Program *ebpf.ProgramSpec  `ebpf:"sample_program"`
		UseMapB *ebpf.VariableSpec `ebpf:"__config_use_map_b"`
	}{}
	require.NoError(t, spec.Assign(&obj))

	blocks, err := MakeBlocks(obj.Program.Instructions)
	require.NoError(t, err)

	noElim, err := Reachability(blocks, obj.Program.Instructions, VariableSpecs(spec.Variables))
	require.NoError(t, err)

	assert.EqualValues(t, 5, noElim.count(), "All blocks should be live")
	assert.Equal(t, noElim.count(), noElim.countLive())

	iter := noElim.LiveInstructions(obj.Program.Instructions)
	assert.NotNil(t, iter)
	var found bool
	for ins, live := range iter {
		assert.True(t, live)
		if ins.Reference() == "map_a" {
			found = true
		}
	}
	assert.True(t, found, "map_a reference should be in live instructions")

	require.NoError(t, obj.UseMapB.Set(true))
	elim, err := Reachability(blocks, obj.Program.Instructions, VariableSpecs(spec.Variables))
	require.NoError(t, err)

	assert.False(t, elim.isLive(1), "Second block with map_a reference should be dead")
	assert.Equal(t, elim.count()-1, elim.countLive())

	iter = elim.LiveInstructions(obj.Program.Instructions)
	assert.NotNil(t, iter)
	for ins, live := range iter {
		if !live {
			continue
		}
		assert.NotEqual(t, "map_a", ins.Reference(), "map_a should not be live")
	}

	// Reachability should fail when called a second time on the same Blocks.
	_, err = Reachability(elim, obj.Program.Instructions, VariableSpecs(spec.Variables))
	assert.Error(t, err)
}

var _ VariableSpec = (*mockVarSpec)(nil)

type mockVarSpec struct {
	mapName string
	offset  uint64
	size    uint64
	value   uint64
}

func (mvs *mockVarSpec) MapName() string {
	return mvs.mapName
}
func (mvs *mockVarSpec) Offset() uint64 {
	return mvs.offset
}
func (mvs *mockVarSpec) Size() uint64 {
	return mvs.size
}
func (mvs *mockVarSpec) Get(out any) error {
	switch out := out.(type) {
	case *int64:
		*out = int64(mvs.value)
		return nil
	case *int32:
		*out = int32(mvs.value)
		return nil
	case *int16:
		*out = int16(mvs.value)
		return nil
	case *int8:
		*out = int8(mvs.value)
	default:
		panic(fmt.Sprintf("unsupported type %T", out))
	}

	return nil
}
func (mvs *mockVarSpec) Constant() bool {
	return true
}

// This tests asserts that when the "map pointer" instruction exists in a previous
// basic block, that we can resolve this. This may happen when the same config
// variable is used multiple times and the compiler decides to reuse the pointer
// instead of re-emitting the instruction.
func TestReachabilityPointerReuse(t *testing.T) {
	const offset = 0

	insns := asm.Instructions{
		// Load the pointer to the config variable into a register
		asm.LoadMapValue(asm.R0, 0, offset).WithReference("map"),
		// Make a branch to go to exit (condition isn't important)
		// This creates a separate basic block
		asm.JEq.Imm(asm.R1, 0, "exit"),

		// In this basic block, we dereference the pointer
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		// Add a random instruction in the middle, this can happen
		asm.Mov.Reg(asm.R2, asm.R3),
		// Here is our conditional branch on R1 which is the config value.
		asm.JEq.Imm(asm.R1, 1, "a_enabled_branch"),

		// This branch is eliminated if `enable_a` == 1
		asm.Mov.Imm(asm.R0, 0),
		asm.Ja.Label("exit"),

		asm.Mov.Imm(asm.R0, 1).WithSymbol("a_enabled_branch"),
		asm.Return().WithSymbol("exit"),
	}

	// Marshal instructions to fix up references.
	require.NoError(t, insns.Marshal(io.Discard, binary.LittleEndian))

	blocks, err := computeBlocks(insns)
	require.NoError(t, err)

	eliminated, err := Reachability(blocks, insns, map[string]VariableSpec{
		"enable_a": &mockVarSpec{"map", offset, uint64(asm.Word.Sizeof()), 1},
	})
	require.NoError(t, err)

	assert.EqualValues(t, 5, eliminated.count())
	assert.NotEqual(t, eliminated.count(), eliminated.countLive())
	assert.True(t, eliminated.isLive(0))
	assert.True(t, eliminated.isLive(1))
	assert.False(t, eliminated.isLive(2))
	assert.True(t, eliminated.isLive(3))
	assert.True(t, eliminated.isLive(4))
}

// This tests asserts that we do basic block analysis and dead code elimination
// correctly when "long jumps" are used. These are jumps with 32 bit offsets
// instead of 16 bit offsets. Something the compiler can emit when programs
// get large and compilation happens with -mcpu=v4
func TestReachabilityLongJump(t *testing.T) {
	const offset = 0
	insns := asm.Instructions{
		// Load the pointer to the config variable into a register
		asm.LoadMapValue(asm.R0, 0, offset).WithReference("map"),
		// Dereference the pointer, getting the actual config value
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		// If `a_enabled` is 0, skip over the long jump
		asm.JEq.Imm(asm.R1, 0, "no_long_jump"),

		// Jump over the next two instructions, to R0 = 1 + exit
		asm.LongJump("a_enabled_branch"),

		// If we are here, `a_enabled` is 0, return 0
		asm.Mov.Imm(asm.R0, 0).WithSymbol("no_long_jump"),
		asm.Return(),

		// If we are here, `a_enabled` is 1, return 1
		asm.Mov.Imm(asm.R0, 1).WithSymbol("a_enabled_branch"),
		asm.Return(),
	}

	// Marshal instructions to fix up references.
	require.NoError(t, insns.Marshal(io.Discard, binary.LittleEndian))

	blocks, err := computeBlocks(insns)
	require.NoError(t, err)
	assert.EqualValues(t, 4, blocks.count())

	disabled, err := Reachability(blocks, insns, map[string]VariableSpec{
		"enable_a": &mockVarSpec{"map", offset, uint64(asm.Word.Sizeof()), 0},
	})
	require.NoError(t, err)

	// Block state should be as follows:
	// 0: live, it's the entry point
	// 1: dead, since it is skipped by the first branch
	// 2: live, we've determined the first branch is always taken
	// 3: dead, since it's the target of the long jump that is never taken
	assert.NotEqual(t, disabled.count(), disabled.countLive())
	assert.True(t, disabled.isLive(0))
	assert.False(t, disabled.isLive(1))
	assert.True(t, disabled.isLive(2))
	assert.False(t, disabled.isLive(3))

	enabled, err := Reachability(blocks, insns, map[string]VariableSpec{
		"enable_a": &mockVarSpec{"map", offset, uint64(asm.Word.Sizeof()), 1},
	})
	require.NoError(t, err)

	// Block state should be as follows:
	// 0: live, it's the entry point
	// 1: live, we've determined the first branch insn is never taken
	// 2: dead, the long jump is taken
	// 3: live, target of the long jump
	assert.NotEqual(t, enabled.count(), enabled.countLive())
	assert.True(t, enabled.isLive(0))
	assert.True(t, enabled.isLive(1))
	assert.False(t, enabled.isLive(2))
	assert.True(t, enabled.isLive(3))
}

// Test that Reachability can be called concurrently. This is a regression test
// for data races in Blocks and Block. Block should never be modified by
// reachability analysis as it is shared across all users of (copies of) a
// CollectionSpec.
func TestReachabilityConcurrent(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("../testdata/unused-map-pruning.o")
	require.NoError(t, err)

	obj := struct {
		Program *ebpf.ProgramSpec  `ebpf:"sample_program"`
		UseMapB *ebpf.VariableSpec `ebpf:"__config_use_map_b"`
	}{}
	require.NoError(t, spec.Assign(&obj))

	// Predict first branch as taken.
	obj.UseMapB.Set(true)

	blocks, err := computeBlocks(obj.Program.Instructions)
	require.NoError(t, err)

	var eg errgroup.Group
	for range 2 {
		eg.Go(func() error {
			_, err := Reachability(blocks, obj.Program.Instructions, VariableSpecs(spec.Variables))
			return err
		})
	}
	require.NoError(t, eg.Wait())
}

func BenchmarkReachability(b *testing.B) {
	b.ReportAllocs()

	insns := branchingProg(b, 1000)

	blocks, err := computeBlocks(insns)
	require.NoError(b, err)

	for b.Loop() {
		_, err = Reachability(blocks, insns, nil)
		require.NoError(b, err)
	}
}
