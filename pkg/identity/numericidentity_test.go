// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

func TestLocalIdentity(t *testing.T) {
	localID := NumericIdentity(IdentityScopeLocal | 1)
	require.True(t, localID.HasLocalScope())

	maxClusterID := NumericIdentity(cmtypes.DefaultClusterInfo.MaxConnectedClusters | 1)
	require.False(t, maxClusterID.HasLocalScope())

	require.False(t, ReservedIdentityWorld.HasLocalScope())
}

func TestClusterID(t *testing.T) {
	tests := []struct {
		name      string
		cinfo     cmtypes.ClusterInfo
		identity  uint32
		clusterID uint32
	}{
		{
			name:      "clustermesh255-zero",
			cinfo:     cmtypes.DefaultClusterInfo,
			identity:  0x000000,
			clusterID: 0,
		},
		{
			name:      "clustermesh255-mid",
			cinfo:     cmtypes.DefaultClusterInfo,
			identity:  0x2A0000,
			clusterID: 42,
		},
		{
			name:      "clustermesh255-max",
			cinfo:     cmtypes.DefaultClusterInfo,
			identity:  cmtypes.DefaultClusterInfo.MaxConnectedClusters << cmtypes.DefaultClusterInfo.GetClusterIDShift(),
			clusterID: cmtypes.DefaultClusterInfo.MaxConnectedClusters,
		},
		{
			name:      "clustermesh511-max",
			cinfo:     cmtypes.ClusterInfo{MaxConnectedClusters: cmtypes.ClusterIDExt511},
			identity:  cmtypes.ClusterIDExt511 << (cmtypes.ClusterInfo{MaxConnectedClusters: cmtypes.ClusterIDExt511}).GetClusterIDShift(),
			clusterID: cmtypes.ClusterIDExt511,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.clusterID, NumericIdentity(tt.identity).ClusterID(tt.cinfo))
		})
	}
}

func TestGetAllReservedIdentities(t *testing.T) {
	allReservedIdentities := GetAllReservedIdentities()
	require.NotNil(t, allReservedIdentities)
	require.Len(t, allReservedIdentities, len(reservedIdentities))
	for i, id := range allReservedIdentities {
		// NOTE: identity 0 is unknown, so the reserved identities start at 1
		// hence the plus one here.
		require.Equal(t, uint32(i+1), id.Uint32())
	}
}

func TestAsUint32Slice(t *testing.T) {
	nids := NumericIdentitySlice{2, 42, 42, 1, 1024, 1}
	uint32Slice := nids.AsUint32Slice()
	require.NotNil(t, uint32Slice)
	require.Len(t, uint32Slice, len(nids))
	for i, nid := range nids {
		require.Equal(t, nid.Uint32(), uint32Slice[i])
	}
}

func TestGetClusterIDShift(t *testing.T) {
	tests := []struct {
		name                   string
		maxConnectedClusters   uint32
		expectedClusterIDShift uint32
		expectedClusterIDBits  uint32
	}{
		{
			name:                   "clustermesh255",
			maxConnectedClusters:   255,
			expectedClusterIDShift: 16,
			expectedClusterIDBits:  8,
		},
		{
			name:                   "clustermesh511",
			maxConnectedClusters:   511,
			expectedClusterIDShift: 15,
			expectedClusterIDBits:  9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cinfo := cmtypes.ClusterInfo{MaxConnectedClusters: tt.maxConnectedClusters}
			assert.Equal(t, tt.expectedClusterIDShift, cinfo.GetClusterIDShift())
			assert.Equal(t, tt.expectedClusterIDBits, cinfo.GetClusterIDBits())
		})
	}
}
