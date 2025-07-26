// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedRemoveUnusedMaps(t *testing.T) {
	testutils.PrivilegedTest(t)

	spec, err := ebpf.LoadCollectionSpec("testdata/unused-map-pruning.o")
	require.NoError(t, err)

	obj := struct {
		Program *ebpf.ProgramSpec  `ebpf:"sample_program"`
		UseMapB *ebpf.VariableSpec `ebpf:"__config_use_map_b"`
	}{}
	require.NoError(t, spec.Assign(&obj))

	// Initially, all maps should be kept.
	keep, err := removeUnusedMaps(spec, nil)
	require.NoError(t, err)
	assert.True(t, keep.Has("map_a"))

	coll, err := ebpf.NewCollection(spec)
	assert.NoError(t, err, "Loading Collection without customizations should succeed")

	assert.NoError(t, verifyUnusedMaps(coll, nil))

	// When setting use_map_b to true, map_a should be pruned.
	require.NoError(t, obj.UseMapB.Set(true))
	keep, err = removeUnusedMaps(spec, nil)
	require.NoError(t, err)

	assert.False(t, keep.Has("map_a"))
	assert.Nil(t, spec.Maps["map_a"])
	assert.True(t, slices.ContainsFunc(obj.Program.Instructions, func(ins asm.Instruction) bool {
		return ins.Constant == poisonedMapLoad
	}), "At least one instruction should have been poisoned")

	coll, err = ebpf.NewCollection(spec)
	assert.NoError(t, err, "Loading Collection should succeed with map_a pruned and pointer poisoned")

	assert.NoError(t, verifyUnusedMaps(coll, nil))
}
