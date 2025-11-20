// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"errors"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/testutils"
)

func mustNewCollection(t *testing.T, spec *ebpf.CollectionSpec) *ebpf.Collection {
	t.Helper()
	coll, err := ebpf.NewCollection(spec)
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		require.NoError(t, ve)
	}
	require.NoError(t, err)
	return coll
}

func TestPrivilegedUnusedMaps(t *testing.T) {
	testutils.PrivilegedTest(t)

	spec, err := ebpf.LoadCollectionSpec("testdata/unused-map-pruning.o")
	require.NoError(t, err)

	obj := struct {
		Program      *ebpf.ProgramSpec  `ebpf:"entry"`
		UseMapA      *ebpf.VariableSpec `ebpf:"__config_use_map_a"`
		UseMapB      *ebpf.VariableSpec `ebpf:"__config_use_map_b"`
		UseMapStatic *ebpf.VariableSpec `ebpf:"__config_use_map_static"`
		UseMapGlobal *ebpf.VariableSpec `ebpf:"__config_use_map_global"`
	}{}
	require.NoError(t, spec.Assign(&obj))

	// Enable as many maps as possible.
	require.NoError(t, obj.UseMapA.Set(true))
	require.NoError(t, obj.UseMapB.Set(true))
	require.NoError(t, obj.UseMapStatic.Set(true))
	require.NoError(t, obj.UseMapGlobal.Set(true))

	reach, err := computeReachability(spec)
	require.NoError(t, err)
	err = removeUnusedMaps(spec, nil, reach, nil)
	require.NoError(t, err)

	assert.NotNil(t, spec.Maps["map_a"])
	assert.NotNil(t, spec.Maps["map_b"])
	assert.NotNil(t, spec.Maps["map_static"])
	assert.NotNil(t, spec.Maps["map_global"])
	assert.False(t, slices.ContainsFunc(obj.Program.Instructions, func(ins asm.Instruction) bool {
		return ins.Constant == poisonedMapLoad
	}), "No instruction should have been poisoned")

	coll := mustNewCollection(t, spec)
	freed, err := freedMaps(coll, nil)
	assert.NoError(t, err)
	assert.Empty(t, freed)

	// Disable as many maps as possible.
	require.NoError(t, obj.UseMapA.Set(false))
	require.NoError(t, obj.UseMapB.Set(false))
	require.NoError(t, obj.UseMapStatic.Set(false))
	require.NoError(t, obj.UseMapGlobal.Set(false))

	reach, err = computeReachability(spec)
	require.NoError(t, err)
	err = removeUnusedMaps(spec, nil, reach, nil)
	require.NoError(t, err)

	assert.Nil(t, spec.Maps["map_a"])
	assert.Nil(t, spec.Maps["map_b"])
	assert.Nil(t, spec.Maps["map_static"])
	assert.Nil(t, spec.Maps["map_global"])
	assert.True(t, slices.ContainsFunc(obj.Program.Instructions, func(ins asm.Instruction) bool {
		return ins.Constant == poisonedMapLoad
	}), "At least one instruction should have been poisoned")

	coll = mustNewCollection(t, spec)
	freed, err = freedMaps(coll, nil)
	assert.NoError(t, err)
	assert.Empty(t, freed)
}

func TestPrivilegedUnusedMapsFalseNegative(t *testing.T) {
	testutils.PrivilegedTest(t)

	spec, err := ebpf.LoadCollectionSpec("testdata/unused-map-false-negative.o")
	require.NoError(t, err)

	reach, err := computeReachability(spec)
	require.NoError(t, err)

	err = removeUnusedMaps(spec, nil, reach, nil)
	require.NoError(t, err)

	coll := mustNewCollection(t, spec)
	freed, err := freedMaps(coll, nil)
	assert.NoError(t, err)
	assert.Contains(t, freed, "unused_map")
}

// Regression test for removeUnusedMaps modifying the fixed set.
func TestUnusedMapsFixedSet(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("testdata/unused-map-pruning.o")
	require.NoError(t, err)

	reach, err := computeReachability(spec)
	require.NoError(t, err)

	orig := set.NewSet("test")
	fixed := orig.Clone()

	err = removeUnusedMaps(spec, &fixed, reach, nil)
	require.NoError(t, err)

	assert.True(t, orig.Equal(fixed))
}
