// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
)

func TestAllAggregates(t *testing.T) {
	// Validate that the aggregates evaluate to themselves:

	for _, nid := range AllAggregates {
		require.True(t, isAggregate(nid))
	}

	// check all identities
	// Should only take a second or two.
	// Validates that all aggregate identities are known.
	for i := range (identity.IdentityScopeRemoteNode | identity.MaxAllocatorLocalIdentity) / 100 {
		nid := i * 100
		// duplicate of AllAggregates for efficiency.
		switch nid {
		case 0, 6, 2:
			require.True(t, isAggregate(nid))
		default:
			require.False(t, isAggregate(nid))
		}
	}
}

func TestIsAggregate(t *testing.T) {
	for i, tc := range []struct {
		in, out identity.NumericIdentity
	}{
		{0, 0},
		{identity.ReservedIdentityHost, 0},
		{identity.ReservedIdentityRemoteNode, 6},
		{identity.ReservedIdentityKubeAPIServer, 6},
		{identity.ReservedCoreDNS, 0},
		{identity.MinLocalIdentity, 2},
		{identity.MaxLocalIdentity, 2},
		{identity.ReservedIdentityWorld, 2},
		{identity.ReservedIdentityWorldIPv4, 2},
		{identity.ReservedIdentityWorldIPv6, 2},
		{identity.IdentityScopeRemoteNode, 6},
		{identity.IdentityScopeRemoteNode + 100, 6},
	} {
		require.Equal(t, tc.out, aggregateFor(tc.in), "idx %d ID %d", i, tc.in)
	}
}
