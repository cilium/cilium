// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPruneExclusionTestMethods(t *testing.T) {
	pe := NewPruneExclusion()

	route1 := DesiredRouteKey{
		Owner:    nil,
		Table:    TableMain,
		Prefix:   netip.MustParsePrefix("192.168.0.0/24"),
		Priority: 0,
	}
	route2 := DesiredRouteKey{
		Owner:    nil,
		Table:    TableMain,
		Prefix:   netip.MustParsePrefix("192.168.1.0/24"),
		Priority: 0,
	}
	require.True(t, pe.Add(route1))
	require.True(t, pe.Add(route2))

	require.Equal(t, map[DesiredRouteKey]struct{}{
		route1: {},
		route2: {},
	}, pe.SnapshotForTest())

	excluded := pe.DrainForTest()
	require.Len(t, excluded, 2)
	require.Equal(t, map[DesiredRouteKey]struct{}{
		route1: {},
		route2: {},
	}, excluded)

	require.Nil(t, pe.SnapshotForTest())

	require.Nil(t, pe.DrainForTest())

	// Add should do nothing after the exclusion set has been consumed.
	require.False(t, pe.Add(route1))
	require.Nil(t, pe.DrainForTest())
}
