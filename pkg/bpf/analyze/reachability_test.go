// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"encoding/binary"
	"io"
	"iter"
	"math"
	"structs"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
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
	for iter, live := range r.Instructions() {
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

func isLive(r *Reachable, id uint64) bool {
	return r.l.Get(id)
}

func countAll(r *Reachable) uint64 {
	return r.blocks.count()
}

func countLive(r *Reachable) uint64 {
	return r.l.Popcount()
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
		SymK    *ebpf.VariableSpec `ebpf:"__config_sym_k"`
		SymL    *ebpf.VariableSpec `ebpf:"__config_sym_l"`
	}{}
	require.NoError(t, spec.Assign(&obj))
	insns := obj.Program.Instructions

	blocks, err := MakeBlocks(insns)
	require.NoError(t, err)

	ur, err := Reachability(blocks, insns, spec.Variables)
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
	require.NoError(t, obj.SymK.Set(int16(1)))
	require.NoError(t, obj.SymL.Set(uint32(1)))

	rr, err := Reachability(blocks, obj.Program.Instructions, spec.Variables)
	require.NoError(t, err)

	allReachable(t, insns, rr)
}

// Load a map value pointer in one block and dereference in another. This is
// common in real-world programs even if the config variable is only used once.
//
// The compiler is free to even insert a jump between the load and dereference
// if the other branch value is already in a register or if the other branch
// condition is deemed more likely.
func TestReachabilityBacktrackBlock(t *testing.T) {
	insns := asm.Instructions{
		// Load the pointer to the config variable into a register.
		asm.LoadMapValue(asm.R0, 0, 0).WithReference(".rodata").WithSymbol("prog"),
		// Make a branch, ending the block.
		asm.JEq.Imm(asm.R1, 0, "exit"),

		// Dereference the map pointer.
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Byte),
		// Random instruction.
		asm.Mov.Reg(asm.R2, asm.R3),
		// Branch on the dereferenced value.
		asm.JEq.Imm(asm.R1, 1, "enabled"),

		// This branch is eliminated if `enable_a` == 1
		asm.Mov.Imm(asm.R0, 0),
		asm.Ja.Label("exit"),

		// Separate block since it's a branch target.
		asm.Mov.Imm(asm.R0, 1).WithSymbol("enabled"),

		// Exit block.
		asm.Return().WithSymbol("exit"),
	}

	// Marshal instructions to fix up references.
	require.NoError(t, insns.Marshal(io.Discard, binary.LittleEndian))

	b, err := computeBlocks(insns)
	require.NoError(t, err)

	r, err := Reachability(b, insns, map[string]*ebpf.VariableSpec{
		"enable_a": {SectionName: ".rodata", Offset: 0, Value: []byte{1}},
	})
	require.NoError(t, err)

	assert.EqualValues(t, 5, countAll(r))
	assert.NotEqual(t, countAll(r), countLive(r))
	assert.True(t, isLive(r, 0))
	assert.True(t, isLive(r, 1))
	assert.False(t, isLive(r, 2))
	assert.True(t, isLive(r, 3))
	assert.True(t, isLive(r, 4))
}

// This tests asserts that we do basic block analysis and dead code elimination
// correctly when "long jumps" are used. These are jumps with 32 bit offsets
// instead of 16 bit offsets. Something the compiler can emit when programs
// get large and compilation happens with -mcpu=v4
func TestReachabilityLongJump(t *testing.T) {
	insns := asm.Instructions{
		// Load the pointer to the config variable into a register
		asm.LoadMapValue(asm.R0, 0, 0).WithReference(".rodata").WithSymbol("prog"),
		// Dereference the pointer, getting the actual config value
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Byte),
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

	disabled, err := Reachability(blocks, insns, map[string]*ebpf.VariableSpec{
		"enable_a": {SectionName: ".rodata", Offset: 0, Value: []byte{0}},
	})
	require.NoError(t, err)

	// Block state should be as follows:
	// 0: live, it's the entry point
	// 1: dead, since it is skipped by the first branch
	// 2: live, we've determined the first branch is always taken
	// 3: dead, since it's the target of the long jump that is never taken
	assert.NotEqual(t, countAll(disabled), countLive(disabled))
	assert.True(t, isLive(disabled, 0))
	assert.False(t, isLive(disabled, 1))
	assert.True(t, isLive(disabled, 2))
	assert.False(t, isLive(disabled, 3))

	enabled, err := Reachability(blocks, insns, map[string]*ebpf.VariableSpec{
		"enable_a": {SectionName: ".rodata", Offset: 0, Value: []byte{1}},
	})
	require.NoError(t, err)

	// Block state should be as follows:
	// 0: live, it's the entry point
	// 1: live, we've determined the first branch insn is never taken
	// 2: dead, the long jump is taken
	// 3: live, target of the long jump
	assert.NotEqual(t, countAll(enabled), countLive(enabled))
	assert.True(t, isLive(enabled, 0))
	assert.True(t, isLive(enabled, 1))
	assert.False(t, isLive(enabled, 2))
	assert.True(t, isLive(enabled, 3))
}

func TestReachableFuncs(t *testing.T) {
	fn := func(ins asm.Instruction, name string) asm.Instruction {
		return btf.WithFuncMetadata(ins.WithSymbol(name), &btf.Func{Name: name})
	}

	insns := asm.Instructions{
		// prog calls live, but never dead.
		fn(asm.Call.Label("live"), "prog"),
		asm.Return(),

		// live spans multiple blocks; "ret" is a jump label, not a function.
		fn(asm.JEq.Imm(asm.R1, 0, "ret"), "live"),
		asm.Mov.Imm(asm.R0, 1),
		asm.Return().WithSymbol("ret"),

		// dead has no callers and contains a double-wide instruction.
		fn(asm.LoadImm(asm.R0, 0, asm.DWord), "dead"),
		asm.Return(),
	}

	// Marshal instructions to fix up references.
	require.NoError(t, insns.Marshal(io.Discard, binary.LittleEndian))

	blocks, err := computeBlocks(insns)
	require.NoError(t, err)

	r, err := Reachability(blocks, insns, nil)
	require.NoError(t, err)

	next, stop := iter.Pull2(r.Funcs())
	defer stop()

	f, l, ok := next()
	require.True(t, ok)
	assert.Equal(t, "prog", f.Name())
	assert.True(t, l)
	assert.Len(t, f, 1)

	f, l, ok = next()
	require.True(t, ok)
	assert.Equal(t, "live", f.Name())
	assert.True(t, l)
	assert.Len(t, f, 3)

	f, l, ok = next()
	require.True(t, ok)
	assert.Equal(t, "dead", f.Name())
	assert.False(t, l)
	assert.Len(t, f, 1)

	_, _, ok = next()
	assert.False(t, ok)

	// Func-relative indices with pointers into the original insns.
	nextIns, stopIns := iter.Pull2(f.Instructions(insns))
	defer stopIns()

	i, ins, ok := nextIns()
	require.True(t, ok)
	assert.Equal(t, 0, i)
	assert.Same(t, &insns[5], ins)

	i, ins, ok = nextIns()
	require.True(t, ok)
	assert.Equal(t, 1, i)
	assert.Same(t, &insns[6], ins)

	_, _, ok = nextIns()
	assert.False(t, ok)
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
			_, err := Reachability(blocks, obj.Program.Instructions, spec.Variables)
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
