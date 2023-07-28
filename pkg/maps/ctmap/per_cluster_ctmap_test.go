// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS("")
	require.NoError(tb, rlimit.RemoveMemlock(), "Failed to set memlock rlimit")

	// Override the map names to avoid clashing with the real ones.
	ClusterOuterMapNameTestOverride("test")
}

func BenchmarkPerClusterCTMapUpdate(b *testing.B) {
	b.StopTimer()
	setup(b)

	om := newPerClusterCTMap(mapTypeIPv4TCPGlobal)
	require.NotNil(b, om, "Failed to initialize map")

	require.NoError(b, om.OpenOrCreate(), "Failed to create outer map")
	b.Cleanup(func() {
		require.NoError(b, om.Close())
		require.NoError(b, CleanupPerClusterCTMaps(true, true), "Failed to cleanup maps")
	})

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		require.NoError(b, om.createClusterCTMap(1), "Failed to create map")
	}

	b.StopTimer()
}

func BenchmarkPerClusterCTMapLookup(b *testing.B) {
	b.StopTimer()
	setup(b)

	om := newPerClusterCTMap(mapTypeIPv4TCPGlobal)
	require.NotNil(b, om, "Failed to initialize map")

	require.NoError(b, om.OpenOrCreate(), "Failed to create outer map")
	b.Cleanup(func() {
		require.NoError(b, om.Close())
		require.NoError(b, CleanupPerClusterCTMaps(true, true), "Failed to cleanup maps")
	})

	require.NoError(b, om.createClusterCTMap(1), "Failed to create map")

	b.StartTimer()

	key := &PerClusterCTMapKey{1}
	for i := 0; i < b.N; i++ {
		_, err := om.Lookup(key)
		require.NoError(b, err, "Failed to lookup element")
	}

	b.StopTimer()
}

func TestPerClusterCTMaps(t *testing.T) {
	setup(t)

	maps := NewPerClusterCTMaps(true, true)
	for _, om := range []*PerClusterCTMap{maps.tcp4, maps.any4, maps.tcp6, maps.any6} {
		require.NotNil(t, om, "Failed to initialize maps")
	}

	require.NoError(t, maps.OpenOrCreate(), "Failed to create outer maps")
	for _, om := range []*PerClusterCTMap{maps.tcp4, maps.any4, maps.tcp6, maps.any6} {
		require.FileExists(t, bpf.MapPath(om.Map.Name()), "Failed to create outer maps")
	}

	t.Cleanup(func() {
		require.NoError(t, maps.Close())
		require.NoError(t, CleanupPerClusterCTMaps(true, true), "Failed to cleanup maps")
	})

	// ClusterID 0 should never be used
	require.Error(t, maps.CreateClusterCTMaps(0), "ClusterID 0 should never be used")
	require.Error(t, maps.DeleteClusterCTMaps(0), "ClusterID 0 should never be used")
	_, err := GetClusterCTMaps(0, true, true)
	require.Error(t, err, "ClusterID 0 should never be used")

	// ClusterID beyond the ClusterIDMax should never be used
	require.Error(t, maps.CreateClusterCTMaps(cmtypes.ClusterIDMax+1), "ClusterID beyond the ClusterIDMax should never be used")
	require.Error(t, maps.DeleteClusterCTMaps(cmtypes.ClusterIDMax+1), "ClusterID beyond the ClusterIDMax should never be used")
	_, err = GetClusterCTMaps(cmtypes.ClusterIDMax+1, true, true)
	require.Error(t, err, "ClusterID beyond the ClusterIDMax should never be used")

	// Basic update
	require.NoError(t, maps.CreateClusterCTMaps(1), "Failed to create maps")
	require.NoError(t, maps.CreateClusterCTMaps(cmtypes.ClusterIDMax), "Failed to create maps")

	for _, id := range []uint32{1, cmtypes.ClusterIDMax} {
		for _, om := range []*PerClusterCTMap{maps.tcp4, maps.any4, maps.tcp6, maps.any6} {
			// After update, the outer map should be updated with the inner map
			value, err := om.Lookup(&PerClusterCTMapKey{id})
			require.NoError(t, err, "Outer map not updated correctly (id=%v, map=%v)", id, om.Name())
			require.NotZero(t, value, "Outer map not updated correctly (id=%v, map=%v)", id, om.Name())

			// After update, the inner map should exist
			require.FileExists(t, bpf.MapPath(om.newInnerMap(id).Map.Name()), "Inner map not correctly present (id=%v, map=%v)", id, om.Name())
		}

		// After update, it should be possible to get and open the inner map
		ims, err := GetClusterCTMaps(id, true, true)
		require.Len(t, ims, 4, "Retrieved an incorrect number of inner maps")
		for _, im := range ims {
			require.NotNil(t, im, "Failed to get inner map (id=%v, map=%v)", id, im.Name())
			require.NoError(t, err, "Failed to get inner map (id=%v, map=%v)", id, im.Name())
			require.NoError(t, im.Open(), "Failed to open inner map (id=%v, map=%v)", im.Name())
			im.Close()
		}
	}

	// An update for an already existing entry should succeed
	require.NoError(t, maps.CreateClusterCTMaps(cmtypes.ClusterIDMax), "Failed to create maps")

	// Basic get all
	ims := maps.GetAllClusterCTMaps()
	require.Len(t, ims, 8, "Retrieved an unexpected number of maps")

	// Basic delete
	require.NoError(t, maps.DeleteClusterCTMaps(1), "Failed to delete maps")
	require.NoError(t, maps.DeleteClusterCTMaps(cmtypes.ClusterIDMax), "Failed to delete maps")

	for _, id := range []uint32{1, cmtypes.ClusterIDMax} {
		for _, om := range []*PerClusterCTMap{maps.tcp4, maps.any4, maps.tcp6, maps.any6} {
			// After delete, the outer map shouldn't contain the entry
			_, err := om.Lookup(&PerClusterCTMapKey{id})
			require.Error(t, err, "Outer map not updated correctly (id=%v, map=%v)", id, om.Name())

			// After delete, the inner map should not exist
			require.NoFileExists(t, bpf.MapPath(om.newInnerMap(id).Map.Name()), "Inner map not correctly deleted (id=%v, map=%v)", id, om.Name())
		}

		// After delete, it should be no longer be possible to open the inner map
		ims, err := GetClusterCTMaps(id, true, true)
		require.Len(t, ims, 4, "Retrieved an incorrect number of inner maps")
		for _, im := range ims {
			require.NotNil(t, im, "Failed to get inner map (id=%v, map=%v)", id, im.Name())
			require.NoError(t, err, "Failed to get inner map (id=%v, map=%v)", id, im.Name())
			require.Error(t, im.Open(), "Should have failed to open inner map (id=%v, map=%v)", id, im.Name())
		}
	}

	// A deletion for an already deleted entry should succeed
	require.NoError(t, maps.DeleteClusterCTMaps(cmtypes.ClusterIDMax), "Failed to delete maps")
}

func TestPerClusterCTMapsCleanup(t *testing.T) {
	setup(t)

	tests := []struct {
		name            string
		ipv4, ipv6      bool
		present, absent []mapType
	}{
		{
			name:    "IPv4",
			ipv4:    true,
			present: []mapType{mapTypeIPv6TCPGlobal, mapTypeIPv6AnyLocal},
			absent:  []mapType{mapTypeIPv4TCPGlobal, mapTypeIPv4AnyLocal},
		},
		{
			name:    "IPv6",
			ipv6:    true,
			present: []mapType{mapTypeIPv4TCPGlobal, mapTypeIPv4AnyLocal},
			absent:  []mapType{mapTypeIPv6TCPGlobal, mapTypeIPv6AnyLocal},
		},
		{
			name:   "dual",
			ipv4:   true,
			ipv6:   true,
			absent: []mapType{mapTypeIPv4TCPGlobal, mapTypeIPv4AnyLocal, mapTypeIPv6TCPGlobal, mapTypeIPv6AnyLocal},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pick up edge and middle values since filling all slots consumes too much memory.
			ids := []uint32{1, 128, cmtypes.ClusterIDMax}
			gm := NewPerClusterCTMaps(true, true)

			require.NoError(t, gm.OpenOrCreate(), "Failed to create outer maps")
			t.Cleanup(func() {
				require.NoError(t, gm.Close())
				// This also ensures that the cleanup succeeds even if the outer maps don't exist
				require.NoError(t, CleanupPerClusterCTMaps(true, true), "Failed to cleanup maps")
			})

			for _, id := range ids {
				require.NoError(t, gm.CreateClusterCTMaps(id), "Failed to create maps (id=%v)", id)
			}

			require.NoError(t, CleanupPerClusterCTMaps(tt.ipv4, tt.ipv6), "Failed to cleanup maps")

			for _, typ := range tt.present {
				for _, id := range ids {
					require.FileExists(t, bpf.MapPath(ClusterInnerMapName(typ, id)), "Inner map should not have been deleted (id=%v, type=%v)", id, typ.name())
				}
				require.FileExists(t, bpf.MapPath(ClusterOuterMapName(typ)), "Outer map should not have been deleted (type=%v)", typ.name())
			}

			for _, typ := range tt.absent {
				for _, id := range ids {
					require.NoFileExists(t, bpf.MapPath(ClusterInnerMapName(typ, id)), "Inner map should have been deleted (id=%v, type=%v)", id, typ.name())
				}
				require.NoFileExists(t, bpf.MapPath(ClusterOuterMapName(typ)), "Outer map should have been deleted (type=%v)", typ.name())
			}
		})
	}
}
