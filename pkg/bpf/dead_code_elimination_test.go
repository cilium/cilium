// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
)

// This is a simple example where we have a variable `__config_use_map_b` which acts a feature flag.
// When it is set to false, the code that uses `map_b` is dead code and should be eliminated.
// When it is set to true, the code that uses `map_b` is live code and should be kept.
func TestDeadCodeEliminationSimple(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("testdata/unused-map-pruning.o")
	if err != nil {
		t.Fatal("Error loading collection:", err)
	}

	prog := spec.Programs["sample_program"]
	original := makeBlockList(prog.Instructions)

	useMapB := false
	if err := spec.Variables["__config_use_map_b"].Set(useMapB); err != nil {
		t.Fatalf("Error setting variable: %v", err)
	}
	elimFalse := deadCodeElimination(original.Copy(), ebpfVarSpecToVarSpec(spec.Variables))
	if len(elimFalse) == len(original) {
		t.Fatalf("No dead code eliminated, which should happen")
		return
	}
	var falseBlockIDs []int
	for _, b := range elimFalse {
		falseBlockIDs = append(falseBlockIDs, b.id)
	}

	useMapB = true
	if err := spec.Variables["__config_use_map_b"].Set(useMapB); err != nil {
		t.Fatalf("Error setting variable: %v", err)
	}
	elimTrue := deadCodeElimination(original.Copy(), ebpfVarSpecToVarSpec(spec.Variables))
	if len(elimTrue) != len(original) {
		t.Fatalf("Dead code eliminated, which shouldn't happen")
		return
	}
	var trueBlockIDs []int
	for _, b := range elimTrue {
		trueBlockIDs = append(trueBlockIDs, b.id)
	}

	assert.NotEqual(t, falseBlockIDs, trueBlockIDs, "Dead code elimination should be different for different values")
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

// This tests asserts that when the "map pointer" instruction exists in a previous
// basic block, that we can resolve this. This may happen when the same config
// variable is used multiple times and the compiler decides to reuse the pointer
// instead of re-emitting the instruction.
func TestDeadCodeEliminationPointerReuse(t *testing.T) {
	const (
		mapName = ".rodata.config"
		offset  = 0
		size    = asm.Word
	)
	insns := asm.Instructions{
		// Load the pointer to the config variable into a register
		asm.LoadMapValue(asm.R0, 0, offset).WithReference(mapName),
		// Make a branch to go to exit (condition isn't important)
		// This creates a separate basic block
		asm.JEq.Imm(asm.R1, 0, "exit"),

		// In this basic block, we dereference the pointer
		asm.LoadMem(asm.R1, asm.R0, 0, size),
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
	// Marshal the instructions, to fixup references
	_ = insns.Marshal(io.Discard, binary.NativeEndian)

	original := makeBlockList(insns)
	eliminated := deadCodeElimination(original.Copy(), map[string]VariableSpec{
		"enable_a": &mockVarSpec{
			mapName: mapName,
			offset:  offset,
			size:    uint64(asm.Word.Sizeof()),
			value:   1,
		},
	})
	assert.NotEqual(t, original, eliminated, "Dead code elimination should have removed some instructions")
}

// This tests asserts that we do basic block analysis and dead code elimination
// correctly when "long jumps" are used. These are jumps with 32 bit offsets
// instead of 16 bit offsets. Something the compiler can emit when programs
// get large and compilation happens with -mcpu=v4
func TestDeadCodeEliminationLongJump(t *testing.T) {
	const (
		mapName = ".rodata.config"
		offset  = 0
		size    = asm.Word
	)
	insns := asm.Instructions{
		// Load the pointer to the config variable into a register
		asm.LoadMapValue(asm.R0, 0, offset).WithReference(mapName),
		// Dereference the pointer, getting the actual config value
		asm.LoadMem(asm.R1, asm.R0, 0, size),
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
	// Marshal the instructions, to fixup references
	_ = insns.Marshal(io.Discard, binary.NativeEndian)

	original := makeBlockList(insns)
	aDisabled := deadCodeElimination(original.Copy(), map[string]VariableSpec{
		"enable_a": &mockVarSpec{
			mapName: mapName,
			offset:  offset,
			size:    uint64(asm.Word.Sizeof()),
			value:   0,
		},
	})
	assert.NotEqual(t, original, aDisabled, "Dead code elimination should have removed some instructions")

	aEnabled := deadCodeElimination(original.Copy(), map[string]VariableSpec{
		"enable_a": &mockVarSpec{
			mapName: mapName,
			offset:  offset,
			size:    uint64(asm.Word.Sizeof()),
			value:   1,
		},
	})
	assert.NotEqual(t, original, aEnabled, "Dead code elimination should have removed some instructions")

	var aDisabledBlockIDs []int
	for _, b := range aDisabled {
		aDisabledBlockIDs = append(aDisabledBlockIDs, b.id)
	}

	var aEnabledBlockIDs []int
	for _, b := range aEnabled {
		aEnabledBlockIDs = append(aEnabledBlockIDs, b.id)
	}

	assert.NotEqual(t, aDisabledBlockIDs, aEnabledBlockIDs, "Dead code elimination should be different for different values")
}
