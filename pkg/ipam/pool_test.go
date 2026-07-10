// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

func TestCIDRPoolAllowFirstAndLastIPs(t *testing.T) {
	logger := hivetest.Logger(t)

	t.Run("default excludes first and last", func(t *testing.T) {
		pool := newCIDRPool(logger, false, false)
		pool.updatePool([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/28")})

		// /28 = 16 IPs, minus first and last = 14 usable
		require.Equal(t, 14, pool.capacity())

		// First and last IPs should be out of range.
		require.Error(t, pool.allocate(netip.MustParseAddr("10.0.0.0")))
		require.Error(t, pool.allocate(netip.MustParseAddr("10.0.0.15")))

		// Interior IPs should work.
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.1")))
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.14")))
	})

	t.Run("allowFirstIP includes first IP", func(t *testing.T) {
		pool := newCIDRPool(logger, true, false)
		pool.updatePool([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/28")})

		require.Equal(t, 15, pool.capacity())
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.0")))
		require.Error(t, pool.allocate(netip.MustParseAddr("10.0.0.15")))
	})

	t.Run("allowLastIP includes last IP", func(t *testing.T) {
		pool := newCIDRPool(logger, false, true)
		pool.updatePool([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/28")})

		require.Equal(t, 15, pool.capacity())
		require.Error(t, pool.allocate(netip.MustParseAddr("10.0.0.0")))
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.15")))
	})

	t.Run("allowFirstIP and allowLastIP includes all IPs", func(t *testing.T) {
		pool := newCIDRPool(logger, true, true)
		pool.updatePool([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/28")})

		// /28 = 16 IPs, all usable
		require.Equal(t, 16, pool.capacity())

		// First and last IPs should be allocatable.
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.0")))
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.15")))
	})

	t.Run("allowFirstIP and allowLastIP with multiple CIDRs", func(t *testing.T) {
		pool := newCIDRPool(logger, true, true)
		pool.updatePool([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/28"), netip.MustParsePrefix("10.0.0.16/28")})

		require.Equal(t, 32, pool.capacity())

		// First IP of each CIDR should be allocatable.
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.0")))
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.16")))
	})
}

// TestCIDRPoolReclaimsStillAdvertisedReleasedCIDR is a regression test for
// the ENI multi-pool exhaustion reported in cilium/cilium#46598. When a
// released CIDR is still advertised in the CiliumNode (e.g. the operator does
// not physically detach it because release-excess-ips is disabled), the agent
// must be able to reclaim it once demand grows back, instead of stranding it
// in p.released forever and exhausting the pool until a restart.
func TestCIDRPoolReclaimsStillAdvertisedReleasedCIDR(t *testing.T) {
	logger := hivetest.Logger(t)

	// Delegated prefixes: first and last IPs of each /28 are allocatable.
	pool := newCIDRPool(logger, true, true)

	p1 := netip.MustParsePrefix("10.0.0.0/28")
	p2 := netip.MustParsePrefix("10.0.0.16/28")

	// Both prefixes are attached and advertised: 32 usable IPs.
	pool.updatePool([]netip.Prefix{p1, p2})
	require.Equal(t, 32, pool.capacity())

	// Keep p1 in use so it is retained, then drop demand so p2 is released.
	require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.0")))
	require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.1")))

	// neededIPs is the number of free IPs that must remain. With near-zero
	// demand, the unused p2 is released.
	pool.releaseExcessCIDRsMultiPool(0)
	require.Contains(t, pool.released, p2, "p2 should be released")
	require.Equal(t, 14, pool.capacity(), "only p1 remains usable")

	// The operator does NOT detach p2 (release-excess-ips disabled), so it
	// stays advertised. updatePool alone must not reclaim it: the release
	// signal to the operator depends on p2 staying out of the in-use set.
	pool.updatePool([]netip.Prefix{p1, p2})
	require.Contains(t, pool.released, p2, "p2 stays released while merely re-advertised")
	require.Equal(t, 14, pool.capacity())

	// Demand grows back beyond what p1 can satisfy. The agent must reclaim
	// the still-advertised p2 rather than report exhaustion.
	pool.releaseExcessCIDRsMultiPool(20)
	require.NotContains(t, pool.released, p2, "p2 should be reclaimed")
	require.Equal(t, 30, pool.capacity(), "p2's 16 IPs are usable again")

	// p2 is back in the in-use CIDR set, so it is re-advertised to the
	// operator as allocated, and its IPs are allocatable.
	require.Len(t, pool.inUseCIDRs(), 2)
	require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.16")))
}
