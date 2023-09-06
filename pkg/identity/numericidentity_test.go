// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
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
