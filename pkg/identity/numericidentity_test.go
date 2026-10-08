// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

func TestLocalIdentity(t *testing.T) {
	localID := NumericIdentity(IdentityScopeLocal | 1)
	require.True(t, localID.HasLocalScope())

	maxClusterID := NumericIdentity(cmtypes.ClusterIDMax | 1)
	require.False(t, maxClusterID.HasLocalScope())

	require.False(t, ReservedIdentityWorld.HasLocalScope())
}

func TestClusterID(t *testing.T) {
	tests := []struct {
		name      string
		cinfo     cmtypes.ClusterInfo
		identity  NumericIdentity
		clusterID uint32
	}{
		{
			name:      "255-cluster layout zero",
			cinfo:     cmtypes.ClusterInfo{MaxConnectedClusters: 255},
			identity:  NumericIdentity(0x000000),
			clusterID: 0,
		},
		{
			name:      "255-cluster layout regular value",
			cinfo:     cmtypes.ClusterInfo{MaxConnectedClusters: 255},
			identity:  NumericIdentity(42 << 16),
			clusterID: 42,
		},
		{
			name:      "255-cluster layout max value",
			cinfo:     cmtypes.ClusterInfo{MaxConnectedClusters: 255},
			identity:  NumericIdentity(255 << 16),
			clusterID: 255,
		},
		{
			name:      "511-cluster layout regular value",
			cinfo:     cmtypes.ClusterInfo{MaxConnectedClusters: 511},
			identity:  NumericIdentity(42 << 15),
			clusterID: 42,
		},
		{
			name:      "511-cluster layout max value",
			cinfo:     cmtypes.ClusterInfo{MaxConnectedClusters: 511},
			identity:  NumericIdentity(511 << 15),
			clusterID: 511,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.clusterID, tt.identity.ClusterID(tt.cinfo))
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
