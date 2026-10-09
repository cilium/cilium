// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPruneExclusion(t *testing.T) {
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

	excluded := pe.consume()
	require.Len(t, excluded, 2)
	require.Equal(t, map[DesiredRouteKey]struct{}{
		route1: {},
		route2: {},
	}, excluded)

	// A new consume should return nil
	require.Nil(t, pe.consume())

	// Add should do nothing after the exclusion set has been consumed.
	require.False(t, pe.Add(route1))
	require.Nil(t, pe.consume())
}
