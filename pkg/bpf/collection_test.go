// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"path"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedUpgradeMap(t *testing.T) {
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

	spec, err := ebpf.LoadCollectionSpec("testdata/upgrade-map.o")
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

// TestPrivilegedMapReplacementIgnoresPin verifies that a map passed in
// MapReplacements is used by the Collection even if a different, compatible map
// is pinned at the map's pin path, and that the loader leaves that pin alone.
func TestPrivilegedMapReplacementIgnoresPin(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	temp := testutils.TempBPFFS(t)

	spec, err := ebpf.LoadCollectionSpec("testdata/upgrade-map.o")
	require.NoError(t, err)

	// Pin a compatible map that is not the one owned by the caller, e.g. after
	// the original pin was lost and the map was recreated by another load.
	pinned, err := ebpf.NewMapWithOptions(spec.Maps["upgraded_map"], ebpf.MapOptions{PinPath: temp})
	require.NoError(t, err)
	defer pinned.Close()

	replacement := NewMap("upgraded_map", ebpf.Array, &TestKey{}, &TestValue{}, 10, 0)
	require.NoError(t, replacement.CreateUnpinned())
	defer replacement.Close()

	obj := struct {
		UpgradedMap *ebpf.Map `ebpf:"upgraded_map"`
	}{}
	commit, err := LoadAndAssign(logger, &obj, spec, &CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: temp},
		},
		MapReplacements: map[string]*Map{
			"upgraded_map": replacement,
			// Replacements for maps not present in the spec must be ignored.
			"missing_map": replacement,
		},
	})
	require.NoError(t, err)
	require.NoError(t, commit())
	defer obj.UpgradedMap.Close()

	assert.Equal(t, mapID(t, replacement.m), mapID(t, obj.UpgradedMap))

	stillPinned, err := ebpf.LoadPinnedMap(path.Join(temp, "upgraded_map"), nil)
	require.NoError(t, err)
	defer stillPinned.Close()
	assert.Equal(t, mapID(t, pinned), mapID(t, stillPinned))
}

func mapID(tb testing.TB, m *ebpf.Map) ebpf.MapID {
	tb.Helper()

	info, err := m.Info()
	require.NoError(tb, err)
	id, ok := info.ID()
	require.True(tb, ok)
	return id
}
