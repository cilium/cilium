// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
)

func TestAllAggregates(t *testing.T) {
	// Validate that the aggregates evaluate to themselves:

	for _, nid := range AllAggregates {
		require.True(t, isAggregate(nid))
	}

	c := identity.ReservedIdentityAggregateCluster
	m := identity.ReservedIdentityAggregateClusterMesh
	n := identity.ReservedIdentityAggregateRemoteNode
	w := identity.ReservedIdentityAggregateWorld

	// Gather results, we will optionally write them
	// to C test literals to ensure we produce reasonable results
	var expectedIn, expectedOut []identity.NumericIdentity
	// set to True to update C test literals
	writeOutput := false

	check := func(nid identity.NumericIdentity) {
		// duplicate of AllAggregates for efficiency.
		switch nid {
		case 0, c, m, n, w:
			require.True(t, isAggregate(nid))
		default:
			require.False(t, isAggregate(nid))
		}

		if writeOutput {
			expectedIn = append(expectedIn, nid)
			expectedOut = append(expectedOut, aggregateFor(nid))
		}
	}

	// check all interesting identities
	// Should only take a second or two.
	// Validates that all aggregate identities are known.
	for i := range 100 {
		check(identity.NumericIdentity(i))
	}
	for _, nid := range []identity.NumericIdentity{
		101,
		1024,
		0xFFFF,
		identity.IdentityScopeLocal,
		identity.IdentityScopeRemoteNode,
	} {
		check(nid - 1)
		check(nid)
		check(nid + 1)
	}

	if writeOutput {
		err := writeCArray("../../bpf/tests/aggregate_nid_in.txt", expectedIn)
		fmt.Printf("wrote %d entries", len(expectedIn))
		require.NoError(t, err)
		err = writeCArray("../../bpf/tests/aggregate_nid_out.txt", expectedOut)
		require.NoError(t, err)
	}
}

func writeCArray(path string, nids []identity.NumericIdentity) error {
	fp, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	for i, nid := range nids {
		if _, err := fmt.Fprintf(fp, "%d, ", nid); err != nil {
			return err
		}
		if i%10 == 9 {
			if _, err := fmt.Fprintln(fp, ""); err != nil {
				return err
			}
		}
	}
	return fp.Close()
}

func TestIsAggregate(t *testing.T) {
	oldCid := option.Config.ClusterID
	t.Cleanup(func() {
		option.Config.ClusterID = oldCid
	})
	option.Config.ClusterID = 0

	// save typing
	w := identity.ReservedIdentityAggregateWorld
	n := identity.ReservedIdentityAggregateRemoteNode

	for i, tc := range []struct {
		in, out identity.NumericIdentity
	}{
		{0, 0},
		{identity.ReservedIdentityHost, 0},
		{identity.ReservedIdentityRemoteNode, 0},
		{identity.ReservedIdentityKubeAPIServer, 0},
		{identity.ReservedCoreDNS, 11},
		{1001, 11},
		{0x00_01_00_55, 12}, // clustermesh
		{identity.MinLocalIdentity, w},
		{identity.MaxLocalIdentity, w},
		{w, w},
		{identity.ReservedIdentityWorld, 0},
		{identity.ReservedIdentityWorldIPv4, 0},
		{identity.ReservedIdentityWorldIPv6, 0},
		{identity.IdentityScopeRemoteNode, n},
		{identity.IdentityScopeRemoteNode + 100, n},
	} {
		require.Equal(t, tc.out, aggregateFor(tc.in), "index %d ID %d", i, tc.in)
	}

	option.Config.ClusterID = 1

	for i, tc := range []struct {
		in, out identity.NumericIdentity
	}{
		{0, 0},
		{identity.ReservedIdentityHost, 0},
		{identity.ReservedIdentityRemoteNode, 0},
		{identity.ReservedIdentityKubeAPIServer, 0},
		{identity.ReservedCoreDNS, 12},
		{1001, 12},          // Now ths ID is clustermesh
		{0x00_01_00_55, 11}, // now in-cluster
		{identity.MinLocalIdentity, w},
		{identity.MaxLocalIdentity, w},
		{w, w},
		{identity.ReservedIdentityWorld, 0},
		{identity.ReservedIdentityWorldIPv4, 0},
		{identity.ReservedIdentityWorldIPv6, 0},
		{identity.IdentityScopeRemoteNode, n},
		{identity.IdentityScopeRemoteNode + 100, n},
	} {
		require.Equal(t, tc.out, aggregateFor(tc.in), "cluster ID 1, index %d ID %d", i, tc.in)
	}
}
