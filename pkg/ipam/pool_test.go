// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
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

// TestCIDRPoolReleaseExcessDelay ensures an unused CIDR is only released once
// it has stayed unused for the whole release delay.
func TestCIDRPoolReleaseExcessDelay(t *testing.T) {
	logger := hivetest.Logger(t)

	p1 := netip.MustParsePrefix("10.0.0.0/28")
	p2 := netip.MustParsePrefix("10.0.0.16/28")
	delay := time.Minute
	start := time.Now()

	t.Run("released once the delay has elapsed", func(t *testing.T) {
		pool := newCIDRPool(logger, false, false)
		pool.updatePool([]netip.Prefix{p1, p2})
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.1")))

		// p2 is unused and in excess, but has to wait for the delay.
		pool.releaseExcessCIDRsMultiPool(0, start, delay)
		require.NotContains(t, pool.released, p2)
		require.Contains(t, pool.releaseCandidates, p2)
		require.Len(t, pool.inUseCIDRs(), 2)

		pool.releaseExcessCIDRsMultiPool(0, start.Add(delay-time.Second), delay)
		require.NotContains(t, pool.released, p2)
		require.Len(t, pool.inUseCIDRs(), 2)

		pool.releaseExcessCIDRsMultiPool(0, start.Add(delay), delay)
		require.Contains(t, pool.released, p2)
		require.NotContains(t, pool.releaseCandidates, p2)
		require.Len(t, pool.inUseCIDRs(), 1)
	})

	t.Run("delay restarts when the CIDR is used again", func(t *testing.T) {
		pool := newCIDRPool(logger, false, false)
		pool.updatePool([]netip.Prefix{p1, p2})
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.1")))

		pool.releaseExcessCIDRsMultiPool(0, start, delay)
		require.Contains(t, pool.releaseCandidates, p2)

		// A pending candidate can still be allocated from.
		ip := netip.MustParseAddr("10.0.0.17")
		require.NoError(t, pool.allocate(ip))
		pool.releaseExcessCIDRsMultiPool(0, start.Add(delay/2), delay)
		require.NotContains(t, pool.releaseCandidates, p2)

		// Once unused again, the full delay applies from that point on.
		pool.release(ip)
		pool.releaseExcessCIDRsMultiPool(0, start.Add(delay), delay)
		require.NotContains(t, pool.released, p2)
		pool.releaseExcessCIDRsMultiPool(0, start.Add(delay+delay/2), delay)
		require.NotContains(t, pool.released, p2)
		pool.releaseExcessCIDRsMultiPool(0, start.Add(2*delay), delay)
		require.Contains(t, pool.released, p2)
	})

	t.Run("delay restarts when the CIDR is needed again", func(t *testing.T) {
		pool := newCIDRPool(logger, false, false)
		pool.updatePool([]netip.Prefix{p1, p2})
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.1")))

		pool.releaseExcessCIDRsMultiPool(0, start, delay)
		require.Contains(t, pool.releaseCandidates, p2)

		// p1 has 13 free IPs, so needing 20 keeps p2 around.
		pool.releaseExcessCIDRsMultiPool(20, start.Add(delay), delay)
		require.NotContains(t, pool.releaseCandidates, p2)
		require.NotContains(t, pool.released, p2)
	})
}

// TestCIDRPoolReleaseExcessPreservesOrder ensures releaseExcessCIDRsMultiPool
// keeps the remaining allocators in their original order, as allocateNext
// relies on it to fill CIDRs in the order they are listed in the CRD.
func TestCIDRPoolReleaseExcessPreservesOrder(t *testing.T) {
	logger := hivetest.Logger(t)

	p1 := netip.MustParsePrefix("10.0.0.0/28")
	p2 := netip.MustParsePrefix("10.0.0.16/28")
	p3 := netip.MustParsePrefix("10.0.0.32/28")

	allocatorCIDRs := func(pool *cidrPool) []netip.Prefix {
		cidrs := make([]netip.Prefix, 0, len(pool.ipAllocators))
		for _, ipAllocator := range pool.ipAllocators {
			cidrs = append(cidrs, ipAllocator.CIDR())
		}
		return cidrs
	}

	pool := newCIDRPool(logger, false, false)
	pool.updatePool([]netip.Prefix{p1, p2, p3})

	// Keep every CIDR in use so none of them is released.
	require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.1")))
	require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.17")))
	require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.33")))

	// Call it twice: a single reversal would be undone by a second one.
	pool.releaseExcessCIDRsMultiPool(0, time.Now(), 0)
	require.Equal(t, []netip.Prefix{p1, p2, p3}, allocatorCIDRs(pool))
	pool.releaseExcessCIDRsMultiPool(0, time.Now(), 0)
	require.Equal(t, []netip.Prefix{p1, p2, p3}, allocatorCIDRs(pool))

	// Releasing a CIDR from the middle keeps the others in order.
	pool.release(netip.MustParseAddr("10.0.0.17"))
	pool.releaseExcessCIDRsMultiPool(0, time.Now(), 0)
	require.Contains(t, pool.released, p2)
	require.Equal(t, []netip.Prefix{p1, p3}, allocatorCIDRs(pool))
}
