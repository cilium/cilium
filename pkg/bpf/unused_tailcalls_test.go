// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoveUnusedTailcalls(t *testing.T) {
	logger := hivetest.Logger(t)
	// Use upstream LoadCollectionSpec to defer the call to
	// removeUnusedTailcalls.
	spec, err := ebpf.LoadCollectionSpec("testdata/unreachable-tailcall.o")
	require.NoError(t, err)

	assert.Contains(t, spec.Programs, "cil_entry")
	assert.Contains(t, spec.Programs, "a")
	assert.Contains(t, spec.Programs, "b")
	assert.Contains(t, spec.Programs, "c")
	assert.Contains(t, spec.Programs, "d")
	assert.Contains(t, spec.Programs, "e")

	cpy := spec.Copy()
	obj := struct {
		UseTailB *ebpf.VariableSpec `ebpf:"__config_use_tail_b"`
	}{}
	require.NoError(t, cpy.Assign(&obj))
	require.NoError(t, obj.UseTailB.Set(true))

	reach, err := computeReachability(cpy)
	require.NoError(t, err)
	require.NoError(t, removeUnusedTailcalls(cpy, reach, logger))

	assert.Contains(t, cpy.Programs, "cil_entry")
	assert.Contains(t, cpy.Programs, "a")
	assert.Contains(t, cpy.Programs, "b")
	assert.Contains(t, cpy.Programs, "c")
	assert.NotContains(t, cpy.Programs, "d")
	assert.Contains(t, cpy.Programs, "e")

	cpy = spec.Copy()
	obj = struct {
		UseTailB *ebpf.VariableSpec `ebpf:"__config_use_tail_b"`
	}{}
	require.NoError(t, cpy.Assign(&obj))
	require.NoError(t, obj.UseTailB.Set(false))

	reach, err = computeReachability(cpy)
	require.NoError(t, err)
	require.NoError(t, removeUnusedTailcalls(cpy, reach, logger))

	assert.Contains(t, cpy.Programs, "cil_entry")
	assert.Contains(t, cpy.Programs, "a")
	assert.NotContains(t, cpy.Programs, "b")
	assert.Contains(t, cpy.Programs, "c")
	assert.NotContains(t, cpy.Programs, "d")
	assert.Contains(t, cpy.Programs, "e")
}
