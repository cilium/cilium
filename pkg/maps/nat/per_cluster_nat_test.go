// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS("")
	require.NoError(tb, rlimit.RemoveMemlock(), "Failed to set memlock rlimit")

	// Override the map names to avoid clashing with the real ones.
	ClusterOuterMapNameTestOverride("test")
}

func path(tb testing.TB, m *bpf.Map) string {
	path, err := m.Path()
	require.NoError(tb, err, "Failed to retrieve map path")
	return path
}

func TestPerClusterMaps(t *testing.T) {
	setup(t)

	maps := newPerClusterNATMaps(true, true, option.NATMapEntriesGlobalDefault)
	require.NotNil(t, maps.v4Map, "Failed to initialize maps")
	require.NotNil(t, maps.v6Map, "Failed to initialize maps")

	require.NoError(t, maps.OpenOrCreate(), "Failed to create outer maps")
	require.FileExists(t, path(t, maps.v4Map.Map), "Failed to create outer maps")
	require.FileExists(t, path(t, maps.v6Map.Map), "Failed to create outer maps")

	t.Cleanup(func() {
		require.NoError(t, maps.Close())
		require.NoError(t, CleanupPerClusterNATMaps(true, true), "Failed to cleanup maps")
	})

	// ClusterID 0 should never be used
	require.Error(t, maps.CreateClusterNATMaps(0), "ClusterID 0 should never be used")
	require.Error(t, maps.DeleteClusterNATMaps(0), "ClusterID 0 should never be used")
	_, err := GetClusterNATMap(0, IPv4)
	require.Error(t, err, "ClusterID 0 should never be used")

	// ClusterID beyond the ClusterIDMax should never be used
	require.Error(t, maps.CreateClusterNATMaps(cmtypes.ClusterIDMax+1), "ClusterID beyond the ClusterIDMax should never be used")
	require.Error(t, maps.DeleteClusterNATMaps(cmtypes.ClusterIDMax+1), "ClusterID beyond the ClusterIDMax should never be used")
	_, err = GetClusterNATMap(cmtypes.ClusterIDMax+1, IPv6)
	require.Error(t, err, "ClusterID beyond the ClusterIDMax should never be used")

	// Basic update
	require.NoError(t, maps.CreateClusterNATMaps(1), "Failed to create maps")
	require.NoError(t, maps.CreateClusterNATMaps(cmtypes.ClusterIDMax), "Failed to create maps")

	for _, id := range []uint32{1, cmtypes.ClusterIDMax} {
		for _, om := range []*perClusterNATMap{maps.v4Map, maps.v6Map} {
			// After update, the outer map should be updated with the inner map
			value, err := om.Lookup(&PerClusterNATMapKey{id})
			require.NoError(t, err, "Outer map not updated correctly (id=%v, family=%v)", id, om.family)
			require.NotZero(t, value, "Outer map not updated correctly (id=%v, family=%v)", id, om.family)

			// After update, the inner map should exist
			require.FileExists(t, path(t, &om.newInnerMap(id).Map), "Inner map not correctly present (id=%v, family=%v)", id, om.family)

			// After update, it should be possible to get and open the inner map
			im, err := GetClusterNATMap(id, om.family)
			require.NotNil(t, im, "Failed to get inner map (id=%v, family=%v)", id, om.family)
			require.NoError(t, err, "Failed to get inner map (id=%v, family=%v)", id, om.family)
			require.NoError(t, im.Open(), "Failed to open inner map (id=%v, family=%v)", id, om.family)
			im.Close()
		}
	}

	// An update for an already existing entry should succeed
	require.NoError(t, maps.CreateClusterNATMaps(cmtypes.ClusterIDMax), "Failed to create maps")

	// Basic delete
	require.NoError(t, maps.DeleteClusterNATMaps(1), "Failed to delete maps")
	require.NoError(t, maps.DeleteClusterNATMaps(cmtypes.ClusterIDMax), "Failed to delete maps")

	for _, id := range []uint32{1, cmtypes.ClusterIDMax} {
		for _, om := range []*perClusterNATMap{maps.v4Map, maps.v6Map} {
			// After delete, the outer map shouldn't contain the entry
			_, err := om.Lookup(&PerClusterNATMapKey{id})
			require.Error(t, err, "Outer map not updated correctly (id=%v, family=%v)", id, om.family)

			// After delete, the inner map should not exist
			require.NoFileExists(t, path(t, &om.newInnerMap(id).Map), "Inner map not correctly deleted (id=%v, family=%v)", id, om.family)

			// After delete, it should be no longer be possible to open the inner map
			im, err := GetClusterNATMap(id, om.family)
			require.NotNil(t, im, "Failed to get inner map (id=%v, family=%v)", id, om.family)
			require.NoError(t, err, "Failed to get inner map (id=%v, family=%v)", id, om.family)
			require.Error(t, im.Open(), "Should have failed to open inner map (id=%v, family=%v)", id, om.family)
		}
	}

	// A deletion for an already deleted entry should succeed
	require.NoError(t, maps.DeleteClusterNATMaps(cmtypes.ClusterIDMax), "Failed to delete maps")
}

func TestPerClusterMapsCleanup(t *testing.T) {
	setup(t)

	tests := []struct {
		name       string
		ipv4, ipv6 bool
	}{
		{name: "IPv4", ipv4: true},
		{name: "IPv6", ipv6: true},
		{name: "dual", ipv4: true, ipv6: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pick up edge and middle values since filling all slots consumes too much memory.
			ids := []uint32{1, 128, cmtypes.ClusterIDMax}
			maps := newPerClusterNATMaps(true, true, option.NATMapEntriesGlobalDefault)

			require.NoError(t, maps.OpenOrCreate(), "Failed to create outer maps")
			t.Cleanup(func() {
				require.NoError(t, maps.Close())
				// This also ensures that the cleanup succeeds even if the outer maps don't exist
				require.NoError(t, CleanupPerClusterNATMaps(true, true), "Failed to cleanup maps")
			})

			for _, id := range ids {
				require.NoError(t, maps.CreateClusterNATMaps(id), "Failed to create maps (id=%v)", id)
			}

			require.NoError(t, CleanupPerClusterNATMaps(tt.ipv4, tt.ipv6), "Failed to cleanup maps")

			for _, om := range []*perClusterNATMap{maps.v4Map, maps.v6Map} {
				must := require.FileExists
				if om.family == IPv4 && tt.ipv4 || om.family == IPv6 && tt.ipv6 {
					must = require.NoFileExists
				}

				for _, id := range ids {
					must(t, path(t, &om.newInnerMap(id).Map), "Inner map not correctly deleted (id=%v, family=%v)", id, om.family)
				}

				must(t, path(t, om.Map), "Outer map not correctly deleted (family=%v)", om.family)
			}
		})
	}
}
