// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"structs"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/testutils"
)

// symbols extracts all unique symbol references from insns, ignoring func and
// map references.
func symbols(insns asm.Instructions) map[string]struct{} {
	syms := make(map[string]struct{})

	for _, ins := range insns {
		if ins.IsFunctionReference() || ins.IsLoadFromMap() {
			continue
		}
		if ref := ins.Reference(); ref != "" {
			syms[ref] = struct{}{}
		}
	}

	return syms
}

// eachLiveRef calls fn for each live symbol reference appearing in r.
func eachLiveRef(r *Reachable, fn func(ref string)) {
	for iter, live := range r.Iterate() {
		if !live {
			continue
		}
		ins := iter.Instruction()
		if ins.IsFunctionReference() || ins.IsLoadFromMap() {
			continue
		}
		if ref := ins.Reference(); ref != "" {
			fn(ref)
		}
	}
}

// allUnreachable asserts that all symbols appearing in insns are marked
// unreachable in r.
func allUnreachable(t *testing.T, insns asm.Instructions, r *Reachable) {
	t.Helper()

	syms := symbols(insns)
	eachLiveRef(r, func(ref string) {
		assert.Nil(t, syms[ref], "symbol %q should be unreachable", ref)
	})
}

// allReachable asserts that all symbols appearing in insns are marked live in
// r.
func allReachable(t *testing.T, insns asm.Instructions, r *Reachable) {
	t.Helper()

	syms := symbols(insns)
	eachLiveRef(r, func(ref string) {
		delete(syms, ref)
	})
	assert.Empty(t, syms, "not all symbols are marked live")
}

func TestReachabilitySimple(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("../testdata/reachability.o")
	require.NoError(t, err)

	obj := struct {
		Program *ebpf.ProgramSpec  `ebpf:"entry"`
		SymA    *ebpf.VariableSpec `ebpf:"__config_sym_a"`
		SymB    *ebpf.VariableSpec `ebpf:"__config_sym_b"`
		SymCD   *ebpf.VariableSpec `ebpf:"__config_sym_cd"`
		SymE    *ebpf.VariableSpec `ebpf:"__config_sym_e"`
		SymF    *ebpf.VariableSpec `ebpf:"__config_sym_f"`
		SymG    *ebpf.VariableSpec `ebpf:"__config_sym_g"`
		SymH    *ebpf.VariableSpec `ebpf:"__config_sym_h"`
		SymI    *ebpf.VariableSpec `ebpf:"__config_sym_i"`
		SymJ    *ebpf.VariableSpec `ebpf:"__config_sym_j"`
	}{}
	require.NoError(t, spec.Assign(&obj))
	insns := obj.Program.Instructions

	blocks, err := MakeBlocks(insns)
	require.NoError(t, err)

	ur, err := Reachability(blocks, insns, VariableSpecs(spec.Variables))
	require.NoError(t, err)

	allUnreachable(t, insns, ur)

	type ts struct {
		_ structs.HostLayout

		_     byte
		sym_c bool
		_     [2]byte
		sym_d uint32
	}

	require.NoError(t, obj.SymA.Set(true))
	require.NoError(t, obj.SymB.Set(uint64(math.MaxUint64)))
	require.NoError(t, obj.SymCD.Set(ts{
		sym_c: true,
		sym_d: 1234,
	}))
	require.NoError(t, obj.SymE.Set(int64(-1)))
	require.NoError(t, obj.SymF.Set(int8(-1)))
	require.NoError(t, obj.SymG.Set(int16(-1)))
	require.NoError(t, obj.SymH.Set(int32(-1)))
	require.NoError(t, obj.SymI.Set(true))
	require.NoError(t, obj.SymJ.Set(true))

	rr, err := Reachability(blocks, obj.Program.Instructions, VariableSpecs(spec.Variables))
	require.NoError(t, err)

	allReachable(t, insns, rr)
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
	case []byte:
		switch mvs.size {
		case 1:
			out[0] = byte(mvs.value)
		case 2:
			binary.NativeEndian.PutUint16(out, uint16(mvs.value))
		case 4:
			binary.NativeEndian.PutUint32(out, uint32(mvs.value))
		case 8:
			binary.NativeEndian.PutUint64(out, uint64(mvs.value))
		default:
			return fmt.Errorf("unsupported size %d for byte slice", mvs.size)
		}
	default:
		panic(fmt.Sprintf("unsupported type %T", out))
	}

	return nil
}
func (mvs *mockVarSpec) Constant() bool {
	return true
}

// This tests asserts that we do basic block analysis and dead code elimination
// correctly when "long jumps" are used. These are jumps with 32 bit offsets
// instead of 16 bit offsets. Something the compiler can emit when programs
// get large and compilation happens with -mcpu=v4
func TestReachabilityLongJump(t *testing.T) {
	const offset = 0
	insns := asm.Instructions{
		// Load the pointer to the config variable into a register
		asm.LoadMapValue(asm.R0, 0, offset).WithReference("map").WithSymbol("prog"),
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
	assert.NotEqual(t, disabled.countAll(), disabled.countLive())
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
	assert.NotEqual(t, enabled.countAll(), enabled.countLive())
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
	spec, err := ebpf.LoadCollectionSpec("../testdata/reachability.o")
	require.NoError(t, err)

	obj := struct {
		Program *ebpf.ProgramSpec `ebpf:"entry"`
	}{}
	require.NoError(t, spec.Assign(&obj))

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

func BenchmarkReachabilityBPF(b *testing.B) {
	testutils.BenchmarkFiles(b, testutils.Glob(b, "../../../bpf/*.o"), func(b *testing.B, file string) {
		b.ReportAllocs()

		spec, err := ebpf.LoadCollectionSpec(file)
		require.NoError(b, err)

		blocks := make(map[string]Blocks)
		for name, prog := range spec.Programs {
			blocks[name], err = computeBlocks(prog.Instructions)
			require.NoError(b, err)
		}

		for b.Loop() {
			for name, prog := range spec.Programs {
				_, err = Reachability(blocks[name], prog.Instructions, nil)
				require.NoError(b, err)
			}
		}
	})
}
