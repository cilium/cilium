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

// TestCIDRPoolRegainsOwnershipOfRemovedCIDR is a regression test for
// cilium/cilium#47910. A CIDR which briefly disappears from the CiliumNode CRD
// spec while in use is marked as removed. Once the operator advertises it
// again, we have regained ownership and must allocate from it again, instead of
// keeping it unallocatable for the lifetime of the agent.
func TestCIDRPoolRegainsOwnershipOfRemovedCIDR(t *testing.T) {
	logger := hivetest.Logger(t)

	// Delegated prefixes: first and last IPs of each /28 are allocatable.
	pool := newCIDRPool(logger, true, true)

	p1 := netip.MustParsePrefix("10.0.0.0/28")
	p2 := netip.MustParsePrefix("10.0.0.16/28")

	pool.updatePool([]netip.Prefix{p1, p2})
	require.Equal(t, 32, pool.capacity())

	// Fill up p1 and take a single IP out of p2, so that p2 is in use.
	for range 16 {
		_, err := pool.allocateNext()
		require.NoError(t, err)
	}
	addr, err := pool.allocateNext()
	require.NoError(t, err)
	require.True(t, p2.Contains(addr))

	// The operator transiently stops advertising p2. As p2 is in use,
	// we hold on to its allocator, but stop allocating from it.
	pool.updatePool([]netip.Prefix{p1})
	require.Contains(t, pool.removed, p2, "in-use p2 should be marked as removed")
	require.Equal(t, 0, pool.capacity(), "no IP of p2 is allocatable")
	require.False(t, pool.hasAvailableIPs())
	_, err = pool.allocateNext()
	require.Error(t, err)

	// A removed CIDR must not be reported as free either, otherwise the
	// reclaim logic considers the pool sufficiently provisioned and neither
	// reclaims nor requests any additional CIDR.
	pool.releaseExcessCIDRsMultiPool(8)
	require.Contains(t, pool.removed, p2, "p2 is not ours to release")
	require.Empty(t, pool.released)
	require.Len(t, pool.inUseCIDRs(), 2, "p2 stays advertised to reclaim ownership")

	// The operator advertises p2 again: we regained ownership and its
	// remaining IPs become allocatable.
	pool.updatePool([]netip.Prefix{p1, p2})
	require.NotContains(t, pool.removed, p2, "ownership of p2 should be regained")
	require.Equal(t, 15, pool.capacity())
	addr, err = pool.allocateNext()
	require.NoError(t, err)
	require.True(t, p2.Contains(addr))
}

// TestCIDRPoolRemovedCIDRDoesNotSuppressReclaim asserts that the free IPs of a
// removed CIDR are not counted as available when deciding whether a released
// CIDR must be reclaimed. Counting them reports free IPs which allocateNext
// never hands out, leaving the pool exhausted until the agent restarts.
func TestCIDRPoolRemovedCIDRDoesNotSuppressReclaim(t *testing.T) {
	logger := hivetest.Logger(t)

	// Delegated prefixes: first and last IPs of each /28 are allocatable.
	pool := newCIDRPool(logger, true, true)

	p1 := netip.MustParsePrefix("10.0.0.0/28")
	p2 := netip.MustParsePrefix("10.0.0.16/28")
	p3 := netip.MustParsePrefix("10.0.0.32/28")

	pool.updatePool([]netip.Prefix{p1, p2, p3})
	require.Equal(t, 48, pool.capacity())

	// Fill up p1 and take a single IP out of p2.
	for range 17 {
		_, err := pool.allocateNext()
		require.NoError(t, err)
	}

	// Demand drops, so the unused p3 is released. The operator keeps
	// advertising it, e.g. because release-excess-ips is disabled.
	pool.releaseExcessCIDRsMultiPool(0)
	require.Contains(t, pool.released, p3, "unused p3 should be released")

	// The operator then transiently stops advertising the in-use p2, which is
	// therefore marked as removed. Its 15 free IPs are no longer allocatable.
	pool.updatePool([]netip.Prefix{p1, p3})
	require.Contains(t, pool.removed, p2)
	require.Contains(t, pool.released, p3, "p3 stays released while advertised")
	require.Equal(t, 0, pool.capacity())

	// Demand grows back. The still-advertised p3 must be reclaimed: the free
	// IPs of the removed p2 do not count towards the needed IPs.
	pool.releaseExcessCIDRsMultiPool(8)
	require.NotContains(t, pool.released, p3, "p3 should be reclaimed")
	require.Contains(t, pool.removed, p2, "p2 is still not ours to allocate from")
	require.Equal(t, 16, pool.capacity())

	addr, err := pool.allocateNext()
	require.NoError(t, err)
	require.True(t, p3.Contains(addr))
}

// TestCIDRPoolForgetsRemovedCIDRWithoutAllocator asserts that the removed mark
// does not outlive the allocator it refers to. Otherwise a later allocator for
// the same CIDR would inherit the mark and never hand out any IP.
func TestCIDRPoolForgetsRemovedCIDRWithoutAllocator(t *testing.T) {
	logger := hivetest.Logger(t)

	pool := newCIDRPool(logger, true, true)

	p1 := netip.MustParsePrefix("10.0.0.0/28")
	p2 := netip.MustParsePrefix("10.0.0.16/28")

	pool.updatePool([]netip.Prefix{p1, p2})
	addr := netip.MustParseAddr("10.0.0.16")
	require.NoError(t, pool.allocate(addr))

	// p2 is dropped from the spec while in use, and so marked as removed.
	pool.updatePool([]netip.Prefix{p1})
	require.Contains(t, pool.removed, p2)

	// The last IP of p2 is released, so its allocator is dropped on the next
	// update, and the removed mark must be dropped with it.
	pool.release(addr)
	pool.updatePool([]netip.Prefix{p1})
	require.Empty(t, pool.removed, "removed mark should not outlive the allocator")
	require.Len(t, pool.inUseCIDRs(), 1)

	// p2 is advertised again and is immediately usable.
	pool.updatePool([]netip.Prefix{p1, p2})
	require.Equal(t, 32, pool.capacity())
	require.NoError(t, pool.allocate(addr))
}
