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

func TestPrivilegedRemoveUnusedMaps(t *testing.T) {
	testutils.PrivilegedTest(t)

	spec, err := ebpf.LoadCollectionSpec("testdata/unused-map-pruning.o")
	require.NoError(t, err)

	obj := struct {
		Program *ebpf.ProgramSpec  `ebpf:"entry"`
		UseMapA *ebpf.VariableSpec `ebpf:"__config_use_map_a"`
		UseMapB *ebpf.VariableSpec `ebpf:"__config_use_map_b"`
	}{}
	require.NoError(t, spec.Assign(&obj))

	// Enable as many maps as possible.
	require.NoError(t, obj.UseMapA.Set(true))
	require.NoError(t, obj.UseMapB.Set(true))

	reach, err := computeReachability(spec)
	require.NoError(t, err)
	_, err = removeUnusedMaps(spec, nil, reach)
	require.NoError(t, err)

	assert.NotNil(t, spec.Maps["map_a"])
	assert.NotNil(t, spec.Maps["map_b"])
	assert.False(t, slices.ContainsFunc(obj.Program.Instructions, func(ins asm.Instruction) bool {
		return ins.Constant == poisonedMapLoad
	}), "No instruction should have been poisoned")

	coll := mustNewCollection(t, spec)
	assert.NoError(t, verifyUnusedMaps(coll, nil))

	// Disable as many maps as possible.
	require.NoError(t, obj.UseMapA.Set(false))
	require.NoError(t, obj.UseMapB.Set(false))

	reach, err = computeReachability(spec)
	require.NoError(t, err)
	_, err = removeUnusedMaps(spec, nil, reach)
	require.NoError(t, err)

	assert.Nil(t, spec.Maps["map_a"])
	assert.Nil(t, spec.Maps["map_b"])
	assert.True(t, slices.ContainsFunc(obj.Program.Instructions, func(ins asm.Instruction) bool {
		return ins.Constant == poisonedMapLoad
	}), "At least one instruction should have been poisoned")

	coll = mustNewCollection(t, spec)
	assert.NoError(t, verifyUnusedMaps(coll, nil))
}
