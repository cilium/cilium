// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestRemoveUnreachableTailcalls(t *testing.T) {
	logger := hivetest.Logger(t)
	// Use upstream LoadCollectionSpec to defer the call to
	// removeUnreachableTailcalls.
	spec, err := ebpf.LoadCollectionSpec("testdata/unreachable-tailcall.o")
	require.NoError(t, err)

	assert.Contains(t, spec.Programs, "cil_entry")
	assert.Contains(t, spec.Programs, "a")
	assert.Contains(t, spec.Programs, "b")
	assert.Contains(t, spec.Programs, "c")
	assert.Contains(t, spec.Programs, "d")
	assert.Contains(t, spec.Programs, "e")

	require.NoError(t, removeUnreachableTailcalls(logger, spec))

	assert.Contains(t, spec.Programs, "cil_entry")
	assert.Contains(t, spec.Programs, "a")
	assert.Contains(t, spec.Programs, "b")
	assert.Contains(t, spec.Programs, "c")
	assert.NotContains(t, spec.Programs, "d")
	assert.NotContains(t, spec.Programs, "e")
}

func TestUpgradeMap(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	temp := testutils.TempBPFFS(t)

	// Pin a dummy map in order to test upgrading it.
	_, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       "upgraded_map",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		Pinning:    ebpf.PinByName,
	}, ebpf.MapOptions{PinPath: temp})
	require.NoError(t, err)

	spec, err := LoadCollectionSpec(logger, "testdata/upgrade-map.o")
	require.NoError(t, err)

	// Use LoadAndAssign to make sure commit works through map upgrades. This is a
	// regression test, as [ebpf.Collection.Assign] deletes Map objects from the
	// Collection when successful, causing commit() to fail afterwards if it uses
	// stringly references to Collection.Maps entries.
	obj := struct {
		UpgradedMap *ebpf.Map `ebpf:"upgraded_map"`
	}{}
	commit, err := LoadAndAssign(logger, &obj, spec, &CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: temp},
		},
	})
	require.NoError(t, err)
	require.NoError(t, commit())

	// Check if the map was upgraded correctly.
	assert.True(t, obj.UpgradedMap.IsPinned())
	assert.EqualValues(t, 10, obj.UpgradedMap.MaxEntries())
}
