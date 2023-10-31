// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"sync"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

func (s *IdentityTestSuite) TestLocalIdentity(c *C) {
	localID := NumericIdentity(IdentityScopeLocal | 1)
	c.Assert(localID.HasLocalScope(), Equals, true)

	maxClusterID := NumericIdentity(types.ClusterIDMax | 1)
	c.Assert(maxClusterID.HasLocalScope(), Equals, false)

	c.Assert(ReservedIdentityWorld.HasLocalScope(), Equals, false)
}

func (s *IdentityTestSuite) TestClusterID(c *C) {
	tbl := []struct {
		identity  uint32
		clusterID uint32
	}{
		{
			identity:  0x000000,
			clusterID: 0,
		},
		{
			identity:  0x010000,
			clusterID: 1,
		},
		{
			identity:  0x2A0000,
			clusterID: 42,
		},
		{
			identity:  0xFF0000,
			clusterID: 255,
		},
		{ // make sure we support min/max configuration values
			identity:  types.ClusterIDMin << 16,
			clusterID: types.ClusterIDMin,
		},
		{
			identity:  types.ClusterIDMax << 16,
			clusterID: types.ClusterIDMax,
		},
	}

	for _, item := range tbl {
		c.Assert(NumericIdentity(item.identity).ClusterID(), Equals, item.clusterID)
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
	resetClusterIDInit := func() { clusterIDInit = sync.Once{} }

	tests := []struct {
		name                   string
		maxConnectedClusters   uint32
		expectedClusterIDShift uint32
	}{
		{
			name:                   "clustermesh255",
			maxConnectedClusters:   255,
			expectedClusterIDShift: 16,
		},
		{
			name:                   "clustermesh511",
			maxConnectedClusters:   511,
			expectedClusterIDShift: 15,
		},
	}

	// cleanup state from any previous tests
	resetClusterIDInit()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(resetClusterIDInit)
			cinfo := cmtypes.ClusterInfo{MaxConnectedClusters: tt.maxConnectedClusters}
			cinfo.InitClusterIDMax()
			assert.Equal(t, tt.expectedClusterIDShift, GetClusterIDShift())

			// ensure we cannot change the clusterIDShift after it has been initialized
			for _, tc := range tests {
				if tc.name == tt.name {
					// skip the current test case itself
					continue
				}
				newCinfo := cmtypes.ClusterInfo{MaxConnectedClusters: tc.maxConnectedClusters}
				newCinfo.InitClusterIDMax()
				assert.NotEqual(t, tc.expectedClusterIDShift, GetClusterIDShift())
			}
		})
	}
}
