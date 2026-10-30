// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
)

func TestCIDRPoolAllowFirstAndLastIPs(t *testing.T) {
	logger := hivetest.Logger(t)

	t.Run("default excludes first and last", func(t *testing.T) {
		pool := newCIDRPool(logger, false, false)
		pool.updatePool([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/28")}, false)

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
		pool.updatePool([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/28")}, false)

		require.Equal(t, 15, pool.capacity())
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.0")))
		require.Error(t, pool.allocate(netip.MustParseAddr("10.0.0.15")))
	})

	t.Run("allowLastIP includes last IP", func(t *testing.T) {
		pool := newCIDRPool(logger, false, true)
		pool.updatePool([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/28")}, false)

		require.Equal(t, 15, pool.capacity())
		require.Error(t, pool.allocate(netip.MustParseAddr("10.0.0.0")))
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.15")))
	})

	t.Run("allowFirstIP and allowLastIP includes all IPs", func(t *testing.T) {
		pool := newCIDRPool(logger, true, true)
		pool.updatePool([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/28")}, false)

		// /28 = 16 IPs, all usable
		require.Equal(t, 16, pool.capacity())

		// First and last IPs should be allocatable.
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.0")))
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.15")))
	})

	t.Run("allowFirstIP and allowLastIP with multiple CIDRs", func(t *testing.T) {
		pool := newCIDRPool(logger, true, true)
		pool.updatePool([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/28"), netip.MustParsePrefix("10.0.0.16/28")}, false)

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
	pool.updatePool([]netip.Prefix{p1, p2}, false)
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
	pool.updatePool([]netip.Prefix{p1, p2}, false)
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
	pool.updatePool([]netip.Prefix{p1, p2, p3}, false)

	// Keep every CIDR in use so none of them is released.
	require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.1")))
	require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.17")))
	require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.33")))

	// Call it twice: a single reversal would be undone by a second one.
	pool.releaseExcessCIDRsMultiPool(0)
	require.Equal(t, []netip.Prefix{p1, p2, p3}, allocatorCIDRs(pool))
	pool.releaseExcessCIDRsMultiPool(0)
	require.Equal(t, []netip.Prefix{p1, p2, p3}, allocatorCIDRs(pool))

	// Releasing a CIDR from the middle keeps the others in order.
	pool.release(netip.MustParseAddr("10.0.0.17"))
	pool.releaseExcessCIDRsMultiPool(0)
	require.Contains(t, pool.released, p2)
	require.Equal(t, []netip.Prefix{p1, p3}, allocatorCIDRs(pool))
}

// The tests below cover the cidrPool side of cilium/cilium#47910
// (https://github.com/cilium/cilium/issues/47910): with ENI prefix
// delegation, pods failed with "all CIDR ranges are exhausted" while the
// node held /28s with free IPs, until the agent restarted. Unless noted
// otherwise they use delegated /28 prefixes (allowFirstIP and allowLastIP
// set), so every /28 holds 16 usable IPs.

// delegatedPrefix returns the i-th consecutive /28 starting at 10.0.0.0.
func delegatedPrefix(i int) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i / 16), byte((i % 16) * 16)}), 28)
}

// delegatedAddr returns the j-th address of the i-th /28.
func delegatedAddr(i, j int) netip.Addr {
	p := delegatedPrefix(i).Addr().As4()
	p[3] += byte(j)
	return netip.AddrFrom4(p)
}

// fillDelegatedPrefix allocates the first n addresses of the i-th /28.
func fillDelegatedPrefix(t *testing.T, pool *cidrPool, i, n int) {
	t.Helper()
	for j := range n {
		require.NoError(t, pool.allocate(delegatedAddr(i, j)))
	}
}

func cidrPoolState(pool *cidrPool) string {
	_, used, free, numCIDRs, _ := pool.dump()
	return fmt.Sprintf("capacity()=%d dump(used=%d free=%d numCIDRs=%d) inUseCIDRs=%v removed=%v released=%v",
		pool.capacity(), used, free, numCIDRs, pool.inUseCIDRs(), pool.removed, pool.released)
}

// TestCIDRPoolRegainsRemovedCIDRFromOperator checks that an in-use CIDR that
// drops out of an operator-owned input and is advertised again (EC2
// re-assigning the same /28) becomes allocatable again. Before
// cilium/cilium#47910 it kept its removed mark: it stayed published as in
// use, but allocateNext skipped it.
func TestCIDRPoolRegainsRemovedCIDRFromOperator(t *testing.T) {
	pool := newCIDRPool(hivetest.Logger(t), true, true)

	p0, p1 := delegatedPrefix(0), delegatedPrefix(1)
	pool.updatePool([]netip.Prefix{p0, p1}, true)

	// p0 is full, p1 has one pod.
	fillDelegatedPrefix(t, pool, 0, 16)
	fillDelegatedPrefix(t, pool, 1, 1)

	// One operator write drops p1 from Status.ENI ...
	pool.updatePool([]netip.Prefix{p0}, true)
	require.Contains(t, pool.removed, p1, "precondition: %s removed", p1)
	// ... and a later write re-adds the very same /28.
	pool.updatePool([]netip.Prefix{p0, p1}, true)
	require.NotContains(t, pool.removed, p1)
	require.Len(t, pool.inUseCIDRs(), 2)

	_, err := pool.allocateNext()
	require.NoError(t, err,
		"re-advertised %s has 15 free IPs, allocation must succeed; %s", p1, cidrPoolState(pool))
	require.True(t, pool.hasAvailableIPs(), cidrPoolState(pool))
	require.Equal(t, 14, pool.capacity(), cidrPoolState(pool))
}

// TestCIDRPoolDropsRemovedMarkWithItsAllocator checks that the removed mark
// of a CIDR goes away with its allocator: when the last IP of a removed CIDR
// is released while the CIDR is absent, and the CIDR is advertised again
// later, its fresh allocator is allocatable. This does not depend on the
// input owner (cilium/cilium#47910).
func TestCIDRPoolDropsRemovedMarkWithItsAllocator(t *testing.T) {
	pool := newCIDRPool(hivetest.Logger(t), true, true)

	p0, p1 := delegatedPrefix(0), delegatedPrefix(1)
	pool.updatePool([]netip.Prefix{p0, p1}, false)

	fillDelegatedPrefix(t, pool, 0, 16)
	fillDelegatedPrefix(t, pool, 1, 1)

	// p1 drops out of the input while in use: it is marked removed.
	pool.updatePool([]netip.Prefix{p0}, false)
	// The pod on p1 is deleted while p1 is still absent.
	pool.release(delegatedAddr(1, 0))
	// Next CiliumNode event: the now-empty allocator for p1 is dropped.
	pool.updatePool([]netip.Prefix{p0}, false)
	require.Len(t, pool.inUseCIDRs(), 1, "precondition: allocator for %s has been dropped", p1)
	require.NotContains(t, pool.removed, p1)

	// The operator re-attaches the same /28: a fresh allocator is created.
	pool.updatePool([]netip.Prefix{p0, p1}, false)
	_, err := pool.allocateNext()
	require.NoError(t, err,
		"fresh allocator for %s has 16 free IPs, allocation must succeed; %s", p1, cidrPoolState(pool))
	require.Equal(t, 15, pool.capacity(), cidrPoolState(pool))
}

// TestCIDRPoolReclaimIgnoresFreeIPsOfRemovedCIDRs checks that the free IPs of
// a removed CIDR do not count towards the free-IP buffer, so released but
// still advertised CIDRs are reclaimed when nothing else is allocatable. The
// numbers are those of cilium/cilium#47910: 9 x /28 = 144 IPs, 69 used.
func TestCIDRPoolReclaimIgnoresFreeIPsOfRemovedCIDRs(t *testing.T) {
	pool := newCIDRPool(hivetest.Logger(t), true, true)

	all := make([]netip.Prefix, 9)
	for i := range all {
		all[i] = delegatedPrefix(i)
	}
	pool.updatePool(all, false)
	require.Equal(t, 144, pool.capacity())

	// p0..p3 full (64), p4 has 5 pods (69 used in total).
	for i := range 4 {
		fillDelegatedPrefix(t, pool, i, 16)
	}
	fillDelegatedPrefix(t, pool, 4, 5)
	require.Equal(t, 69, pool.inUseIPCount())

	// Demand is low: the unused p5..p8 are released but stay advertised.
	pool.releaseExcessCIDRsMultiPool(0)
	for i := 5; i < 9; i++ {
		require.Contains(t, pool.released, all[i], "precondition: %s released", all[i])
	}

	// One operator write drops p4 (5 used, 11 free).
	without4 := append(append([]netip.Prefix{}, all[:4]...), all[5:]...)
	pool.updatePool(without4, false)
	require.Contains(t, pool.removed, all[4], "precondition: %s removed", all[4])

	// Agent sync rounds: ENI pre-allocate 8, plus one pending pod per retry.
	var err error
	for _, neededFree := range []int{8, 9, 10, 11} {
		pool.updatePool(without4, false)
		pool.releaseExcessCIDRsMultiPool(neededFree)
		if _, err = pool.allocateNext(); err == nil {
			break
		}
	}
	require.NoError(t, err,
		"released but advertised /28s must be reclaimed when no allocatable IP is left; %s", cidrPoolState(pool))
}

// TestCIDRPoolReleaseIgnoresFreeIPsOfRemovedCIDRs checks that the release
// loop does not count the free IPs of a removed CIDR either, so it does not
// release the only allocatable CIDR (cilium/cilium#47910).
func TestCIDRPoolReleaseIgnoresFreeIPsOfRemovedCIDRs(t *testing.T) {
	pool := newCIDRPool(hivetest.Logger(t), true, true)

	p0, p1, p2 := delegatedPrefix(0), delegatedPrefix(1), delegatedPrefix(2)
	pool.updatePool([]netip.Prefix{p0, p1}, false)

	// p0 is full, p1 has one pod and 15 free IPs.
	fillDelegatedPrefix(t, pool, 0, 16)
	fillDelegatedPrefix(t, pool, 1, 1)

	// The operator replaces p1 by p2 in one write: p1 is removed, p2 is new.
	pool.updatePool([]netip.Prefix{p0, p2}, false)
	require.Contains(t, pool.removed, p1, "precondition: %s removed", p1)

	// The agent wants a buffer of 8 free IPs. Only p2 can provide them.
	pool.releaseExcessCIDRsMultiPool(8)
	require.NotContains(t, pool.released, p2,
		"%s is the only allocatable CIDR and must not be released; %s", p2, cidrPoolState(pool))
	require.Equal(t, 16, pool.capacity(), cidrPoolState(pool))
}

// genericEcho returns the input of the next generic multi-pool update: the
// CIDRs granted by the operator plus the CIDRs the agent itself published in
// Spec.IPAM.Pools.Allocated, which is both its input and its output.
func genericEcho(pool *cidrPool, granted ...netip.Prefix) []netip.Prefix {
	input := slices.Clone(granted)
	for _, c := range pool.inUseCIDRs() {
		if !slices.Contains(input, c.Prefix) {
			input = append(input, c.Prefix)
		}
	}
	return input
}

// TestCIDRPoolGenericEchoDoesNotRegainRemovedCIDR checks that in generic
// multi-pool mode a CIDR X that was removed while in use is never allocated
// from again, although the agent's own echo keeps X in the input, the last
// pod on X is released, and demand rises: the operator may have given X to
// another node. This is the objection to cilium/cilium#47916.
func TestCIDRPoolGenericEchoDoesNotRegainRemovedCIDR(t *testing.T) {
	pool := newCIDRPool(hivetest.Logger(t), true, true)

	p0, x := delegatedPrefix(0), delegatedPrefix(1)
	pool.updatePool([]netip.Prefix{p0, x}, false)
	fillDelegatedPrefix(t, pool, 0, 16)
	fillDelegatedPrefix(t, pool, 1, 1)

	// The operator takes X away, the agent echoes it back as in use.
	pool.updatePool([]netip.Prefix{p0}, false)
	pool.updatePool([]netip.Prefix{p0, x}, false)
	require.Contains(t, pool.removed, x, "precondition: %s removed", x)

	// The pod on X is deleted.
	pool.release(delegatedAddr(1, 0))

	// The echo keeps X in the input while demand rises.
	for _, needed := range []int{1, 8, 16, 32} {
		pool.updatePool([]netip.Prefix{p0, x}, false)
		pool.releaseExcessCIDRsMultiPool(needed)
		addr, err := pool.allocateNext()
		if err == nil {
			require.False(t, x.Contains(addr), "allocated %s from removed %s; %s", addr, x, cidrPoolState(pool))
			pool.release(addr)
		}
		require.False(t, pool.hasAvailableIPs(), "removed %s must not be allocatable; %s", x, cidrPoolState(pool))
	}
}

// TestCIDRPoolGenericEchoReleasesUnusedRemovedCIDR checks that in generic
// multi-pool mode an unused removed CIDR X that the agent's own echo keeps in
// the input is released, stops being published, and loses its removed mark
// once the echo is gone, so that it does not leak.
func TestCIDRPoolGenericEchoReleasesUnusedRemovedCIDR(t *testing.T) {
	pool := newCIDRPool(hivetest.Logger(t), true, true)

	p0, x := delegatedPrefix(0), delegatedPrefix(1)
	pool.updatePool([]netip.Prefix{p0, x}, false)
	fillDelegatedPrefix(t, pool, 0, 4)
	fillDelegatedPrefix(t, pool, 1, 1)

	// The operator takes X away, the agent echoes it back as in use.
	pool.updatePool([]netip.Prefix{p0}, false)
	pool.updatePool(genericEcho(pool, p0), false)
	require.Contains(t, pool.removed, x, "precondition: %s removed", x)
	require.Contains(t, pool.inUseCIDRs(), iputil.PrefixFrom(x), "precondition: %s published", x)

	// The pod on X is deleted.
	pool.release(delegatedAddr(1, 0))

	// Sync rounds: release excess CIDRs, publish, receive the echo.
	for range 3 {
		pool.releaseExcessCIDRsMultiPool(8)
		pool.updatePool(genericEcho(pool, p0), false)
	}

	require.NotContains(t, pool.inUseCIDRs(), iputil.PrefixFrom(x),
		"unused removed %s must stop being published; %s", x, cidrPoolState(pool))
	require.NotContains(t, pool.removed, x, cidrPoolState(pool))
	require.NotContains(t, pool.released, x, cidrPoolState(pool))
	require.Equal(t, 12, pool.capacity(), "only %s is allocatable; %s", p0, cidrPoolState(pool))
}

// TestCIDRPoolRemovedReleasedCIDRStillListed covers a CIDR X that is both
// removed and released (its allocator is gone) while the input still lists
// it.
func TestCIDRPoolRemovedReleasedCIDRStillListed(t *testing.T) {
	p0, x := delegatedPrefix(0), delegatedPrefix(1)

	// setup leaves X removed and released, with p0 holding 12 free IPs.
	setup := func(t *testing.T, authoritative bool) *cidrPool {
		pool := newCIDRPool(hivetest.Logger(t), true, true)
		pool.updatePool([]netip.Prefix{p0, x}, authoritative)
		fillDelegatedPrefix(t, pool, 0, 4)
		fillDelegatedPrefix(t, pool, 1, 1)
		pool.updatePool([]netip.Prefix{p0}, authoritative)
		pool.release(delegatedAddr(1, 0))
		pool.releaseExcessCIDRsMultiPool(8)
		require.Contains(t, pool.removed, x, "precondition: %s removed", x)
		require.Contains(t, pool.released, x, "precondition: %s released", x)
		require.NotContains(t, pool.inUseCIDRs(), iputil.PrefixFrom(x), "precondition: %s not published", x)
		return pool
	}

	// In generic mode this is intended: X is not reclaimed while it is
	// listed, because the listing may be the agent's own echo from before
	// the release, and the operator may have given X to another node. The
	// agent no longer publishes X, so the operator drops it with its next
	// write, which clears the mark. A later grant of X is then usable.
	t.Run("generic mode reclaims it only after the operator dropped it", func(t *testing.T) {
		pool := setup(t, false)

		pool.updatePool([]netip.Prefix{p0, x}, false)
		pool.releaseExcessCIDRsMultiPool(32)
		require.Contains(t, pool.removed, x)
		for {
			addr, err := pool.allocateNext()
			if err != nil {
				break
			}
			require.False(t, x.Contains(addr), "allocated %s from %s; %s", addr, x, cidrPoolState(pool))
		}

		// The operator has processed the agent's publication without X.
		pool.updatePool([]netip.Prefix{p0}, false)
		require.NotContains(t, pool.removed, x, cidrPoolState(pool))
		require.NotContains(t, pool.released, x, cidrPoolState(pool))

		// The operator grants X again.
		pool.updatePool([]netip.Prefix{p0, x}, false)
		addr, err := pool.allocateNext()
		require.NoError(t, err, cidrPoolState(pool))
		require.True(t, x.Contains(addr), "allocated %s, want an IP from %s", addr, x)
	})

	// In ENI mode the listing comes from the operator, so X is regained
	// and can be reclaimed at once.
	t.Run("authoritative input regains and reclaims it", func(t *testing.T) {
		pool := setup(t, true)

		pool.updatePool([]netip.Prefix{p0, x}, true)
		require.NotContains(t, pool.removed, x, cidrPoolState(pool))
		pool.releaseExcessCIDRsMultiPool(32)
		require.NotContains(t, pool.released, x, cidrPoolState(pool))
		require.Equal(t, 28, pool.capacity(), cidrPoolState(pool))
	})
}

// hostPrefixes returns the host prefixes (/32 or /128) of the first n
// addresses of x, e.g. as FromResource derives them from the flattened ENI
// addresses of an operator up to v1.20.
func hostPrefixes(x netip.Prefix, n int) []netip.Prefix {
	out := make([]netip.Prefix, 0, n)
	addr := x.Addr()
	for range n {
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		addr = addr.Next()
	}
	return out
}

// podIPs models the IPs held by pods on the node. allocateNext must never
// return one of them.
type podIPs map[netip.Addr]struct{}

func (pods podIPs) allocNext(t *testing.T, pool *cidrPool, step string) (netip.Addr, bool) {
	t.Helper()
	addr, err := pool.allocateNext()
	if err != nil {
		return netip.Addr{}, false
	}
	require.NotContains(t, pods, addr, "%s: allocateNext returned %s, which a pod already holds; %s",
		step, addr, cidrPoolState(pool))
	pods[addr] = struct{}{}
	return addr, true
}

func (pods podIPs) drain(t *testing.T, pool *cidrPool, step string) {
	t.Helper()
	for range 64 {
		if _, ok := pods.allocNext(t, pool, step); !ok {
			return
		}
	}
}

// requireNoOverlap checks that no two allocators share an allocatable
// address, and that the pool's counts match the distinct addresses.
func requireNoOverlap(t *testing.T, pool *cidrPool) {
	t.Helper()
	var overlaps []string
	used, free := sets.New[netip.Addr](), 0
	pool.mutex.Lock()
	for i, a := range pool.ipAllocators {
		for _, b := range pool.ipAllocators[i+1:] {
			if a.Overlaps(b) {
				overlaps = append(overlaps, a.CIDR().String()+" "+b.CIDR().String())
			}
		}
		a.ForEach(func(addr netip.Addr) { used.Insert(addr) })
		if _, removed := pool.removed[a.CIDR()]; !removed {
			free += a.Free()
		}
	}
	pool.mutex.Unlock()
	require.Empty(t, overlaps, "overlapping allocators")
	require.Equal(t, used.Len(), pool.inUseIPCount(), "in-use IPs must be counted once")
	require.Equal(t, free, pool.capacity())
}

// TestCIDRPoolAbsorbsContainedCIDRs checks that allocators never overlap:
// a CIDR covered by an existing allocator gets no allocator of its own, and
// a CIDR that covers existing allocators absorbs them with their used IPs.
// Overlaps were seen with cilium/cilium#47910 on a v1.20.4 cluster whose
// injected Status.ENI listed the flattened /32 addresses of a removed /28.
func TestCIDRPoolAbsorbsContainedCIDRs(t *testing.T) {
	x := netip.MustParsePrefix("100.64.12.176/28")

	t.Run("host prefixes covered by a removed prefix, which is then regained", func(t *testing.T) {
		pool := newCIDRPool(hivetest.Logger(t), true, true)
		pods := podIPs{}

		pool.updatePool([]netip.Prefix{x}, true)
		for _, a := range []string{"100.64.12.177", "100.64.12.178"} {
			addr := netip.MustParseAddr(a)
			require.NoError(t, pool.allocate(addr))
			pods[addr] = struct{}{}
		}

		// X drops out of the input: removed, allocator kept.
		pool.updatePool(nil, true)
		require.Contains(t, pool.removed, x, "precondition: %s removed", x)

		// The input lists the host prefixes of X: X covers them. They
		// get no allocators, but are still published.
		pool.updatePool(hostPrefixes(x, 16), true)
		want := []iputil.Prefix{iputil.PrefixFrom(x)}
		for _, h := range hostPrefixes(x, 16) {
			want = append(want, iputil.PrefixFrom(h))
		}
		require.Equal(t, want, pool.inUseCIDRs(),
			"host prefixes covered by %s must not get allocators", x)
		require.Len(t, pool.ipAllocators, 1, cidrPoolState(pool))
		_, ok := pods.allocNext(t, pool, "host prefixes listed")
		require.False(t, ok, "removed %s must not be allocatable", x)
		requireNoOverlap(t, pool)

		// X comes back and is regained.
		pool.updatePool([]netip.Prefix{x}, true)
		require.NotContains(t, pool.removed, x)
		pods.drain(t, pool, "regained prefix")
		require.Len(t, pods, 16, cidrPoolState(pool))
		requireNoOverlap(t, pool)
	})

	t.Run("host prefixes covered by a removed prefix, without regain", func(t *testing.T) {
		pool := newCIDRPool(hivetest.Logger(t), true, true)
		pods := podIPs{}

		pool.updatePool([]netip.Prefix{x}, false)
		for _, a := range []string{"100.64.12.177", "100.64.12.178"} {
			addr := netip.MustParseAddr(a)
			require.NoError(t, pool.allocate(addr))
			pods[addr] = struct{}{}
		}

		pool.updatePool(nil, false)
		pool.updatePool(hostPrefixes(x, 16), false)
		pods.drain(t, pool, "host prefixes listed")
		requireNoOverlap(t, pool)

		pool.updatePool([]netip.Prefix{x}, false)
		pods.drain(t, pool, "prefix listed again")
		require.Len(t, pods, 2, "removed %s must not be allocatable; %s", x, cidrPoolState(pool))
		requireNoOverlap(t, pool)
	})

	t.Run("in-use host prefixes are absorbed by their prefix", func(t *testing.T) {
		pool := newCIDRPool(hivetest.Logger(t), true, true)
		pods := podIPs{}

		pool.updatePool(hostPrefixes(x, 4), true)
		pods.drain(t, pool, "host prefixes only")
		require.Len(t, pods, 4)

		// X appears and the host prefixes drop out. They are in use, so
		// they are marked removed, then absorbed by X.
		pool.updatePool([]netip.Prefix{x}, true)
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(x)}, pool.inUseCIDRs(), cidrPoolState(pool))
		require.Empty(t, pool.removed, "absorbed CIDRs lose their removed mark")
		require.Equal(t, 4, pool.inUseIPCount())
		require.Equal(t, 12, pool.capacity())

		freed := netip.MustParseAddr("100.64.12.177")
		pool.release(freed)
		delete(pods, freed)
		require.Equal(t, 13, pool.capacity())

		pods.drain(t, pool, "prefix")
		require.Len(t, pods, 16, cidrPoolState(pool))
		require.Equal(t, 16, pool.inUseIPCount())
		requireNoOverlap(t, pool)
	})

	t.Run("generic mode absorbs a removed host prefix into a granted prefix", func(t *testing.T) {
		pool := newCIDRPool(hivetest.Logger(t), true, true)
		host := hostPrefixes(x, 1)[0]

		pool.updatePool([]netip.Prefix{host}, false)
		require.NoError(t, pool.allocate(host.Addr()))
		pool.updatePool(nil, false)
		require.Contains(t, pool.removed, host, "precondition: %s removed", host)

		// A fresh allocator can only come from the operator, so X is
		// allocatable, and it keeps the IP in use.
		pool.updatePool([]netip.Prefix{x}, false)
		require.Empty(t, pool.removed)
		require.Equal(t, 1, pool.inUseIPCount())
		require.Equal(t, 15, pool.capacity())
		require.ErrorIs(t, pool.allocate(host.Addr()), ipallocator.ErrAllocated)
	})

	t.Run("counts stay exact when a prefix absorbs another", func(t *testing.T) {
		pool := newCIDRPool(hivetest.Logger(t), true, true)
		a, b := delegatedPrefix(0), delegatedPrefix(4)
		parent := netip.MustParsePrefix("10.0.0.0/27") // contains a, not b

		pool.updatePool([]netip.Prefix{a, b}, true)
		require.NoError(t, pool.allocate(delegatedAddr(0, 1)))
		pool.updatePool([]netip.Prefix{a, b, parent}, true)
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(b), iputil.PrefixFrom(parent)}, pool.inUseCIDRs())
		require.Equal(t, 1, pool.inUseIPCount())
		require.Equal(t, 16+31, pool.capacity())
		requireNoOverlap(t, pool)

		// Releasing b would leave 31 < 40 free IPs.
		pool.releaseExcessCIDRsMultiPool(40)
		require.NotContains(t, pool.released, b, cidrPoolState(pool))

		// a is covered by parent from now on.
		pool.updatePool([]netip.Prefix{a, b, parent}, true)
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(b), iputil.PrefixFrom(parent)}, pool.inUseCIDRs())
		requireNoOverlap(t, pool)
	})

	t.Run("reclaimed prefix absorbs an allocator it contains", func(t *testing.T) {
		pool := newCIDRPool(hivetest.Logger(t), true, true)
		parent := netip.MustParsePrefix("10.0.0.0/27")
		sub := netip.MustParsePrefix("10.0.0.16/28")
		p0 := delegatedPrefix(4)

		// parent is unused and released while it stays listed.
		pool.updatePool([]netip.Prefix{p0, parent}, true)
		fillDelegatedPrefix(t, pool, 4, 16)
		pool.releaseExcessCIDRsMultiPool(0)
		require.Contains(t, pool.released, parent, "precondition: %s released", parent)

		// sub is listed as well and gets used.
		pool.updatePool([]netip.Prefix{p0, parent, sub}, true)
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.20")))

		// Demand rises: parent is reclaimed and absorbs sub.
		pool.releaseExcessCIDRsMultiPool(40)
		require.NotContains(t, pool.released, parent, cidrPoolState(pool))
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(p0), iputil.PrefixFrom(parent)}, pool.inUseCIDRs())
		require.Equal(t, 17, pool.inUseIPCount())
		require.Equal(t, 31, pool.capacity())
		requireNoOverlap(t, pool)
	})

	t.Run("reclaimed prefix absorbs a removed allocator it contains", func(t *testing.T) {
		pool := newCIDRPool(hivetest.Logger(t), true, true)
		parent := netip.MustParsePrefix("10.0.0.0/27")
		sub := netip.MustParsePrefix("10.0.0.16/28")
		host := netip.MustParsePrefix("10.0.0.24/32")
		p0, q := delegatedPrefix(4), delegatedPrefix(5)

		// parent and q are unused and released while they stay listed.
		pool.updatePool([]netip.Prefix{p0, parent, q}, true)
		fillDelegatedPrefix(t, pool, 4, 16)
		pool.releaseExcessCIDRsMultiPool(0)
		require.Contains(t, pool.released, parent, "precondition: %s released", parent)
		require.Contains(t, pool.released, q, "precondition: %s released", q)

		// sub is listed and gets used, then drops out of the input while
		// an IP of it is re-assigned as host.
		pool.updatePool([]netip.Prefix{p0, parent, q, sub}, true)
		require.NoError(t, pool.allocate(netip.MustParseAddr("10.0.0.20")))
		pool.updatePool([]netip.Prefix{p0, parent, q, host}, true)
		require.Contains(t, pool.removed, sub, "precondition: %s removed", sub)
		require.Contains(t, pool.inUseCIDRs(), iputil.PrefixFrom(host), "precondition: %s published", host)

		// Demand rises: parent is reclaimed and absorbs the removed sub.
		// The free IPs of sub never counted, so after the reclaim there
		// are 31 >= 20 free IPs, and q stays released.
		pool.releaseExcessCIDRsMultiPool(20)
		require.NotContains(t, pool.released, parent, cidrPoolState(pool))
		require.Contains(t, pool.released, q, "free IPs of removed %s must not be subtracted; %s", sub, cidrPoolState(pool))
		require.Empty(t, pool.removed, cidrPoolState(pool))
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(p0), iputil.PrefixFrom(parent)}, pool.inUseCIDRs(),
			"%s is covered by the allocatable %s now; %s", host, parent, cidrPoolState(pool))
		require.Equal(t, 17, pool.inUseIPCount())
		require.Equal(t, 31, pool.capacity())
		requireNoOverlap(t, pool)
	})

	t.Run("IPv6 host prefix is checked against the allocator window", func(t *testing.T) {
		pool := newCIDRPool(hivetest.Logger(t), true, true)
		wide := netip.MustParsePrefix("2001:db8::/80")
		// The allocator of a /80 covers the first 2^16 addresses only.
		inWindow := netip.MustParsePrefix("2001:db8::ff/128")
		outside := netip.MustParsePrefix("2001:db8::1:0:0/128")

		pool.updatePool([]netip.Prefix{wide, inWindow, outside}, true)
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(wide), iputil.PrefixFrom(outside)}, pool.inUseCIDRs(),
			"only the /128 inside the window is covered")
		requireNoOverlap(t, pool)

		// Restoring IPs works for both, and release frees the right one.
		require.NoError(t, pool.allocate(inWindow.Addr()))
		require.NoError(t, pool.allocate(outside.Addr()))
		require.Equal(t, 2, pool.inUseIPCount())
		pool.release(outside.Addr())
		require.Equal(t, 1, pool.inUseIPCount())
		require.NoError(t, pool.allocate(outside.Addr()))
		requireNoOverlap(t, pool)
	})

	t.Run("IPv6 prefix absorbs removed host prefixes in its window", func(t *testing.T) {
		pool := newCIDRPool(hivetest.Logger(t), true, true)
		wide := netip.MustParsePrefix("2001:db8::/80")
		hosts := hostPrefixes(netip.MustParsePrefix("2001:db8::10/124"), 2)

		pool.updatePool(hosts, true)
		for _, h := range hosts {
			require.NoError(t, pool.allocate(h.Addr()))
		}
		pool.updatePool([]netip.Prefix{wide}, true)
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(wide)}, pool.inUseCIDRs(), cidrPoolState(pool))
		require.Empty(t, pool.removed)
		require.Equal(t, 2, pool.inUseIPCount())
		requireNoOverlap(t, pool)
	})

	t.Run("CIDR partially overlapping an allocator is skipped", func(t *testing.T) {
		// Without allowFirstIP, a /24 does not hand out its network
		// address. A /31 at its start overlaps it without being covered.
		pool := newCIDRPool(hivetest.Logger(t), false, false)
		subnet := netip.MustParsePrefix("10.0.0.0/24")
		edge := netip.MustParsePrefix("10.0.0.0/31")
		network := netip.MustParsePrefix("10.0.0.0/32")

		pool.updatePool([]netip.Prefix{subnet, edge}, false)
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(subnet)}, pool.inUseCIDRs())

		// The network address alone does not overlap the /24's
		// allocatable addresses, so it gets an allocator, as before.
		pool.updatePool([]netip.Prefix{subnet, network}, false)
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(subnet), iputil.PrefixFrom(network)}, pool.inUseCIDRs())
		require.Equal(t, 254+1, pool.capacity())
		requireNoOverlap(t, pool)
	})
}

// TestCIDRPoolPublishesCIDRsCoveredByRemovedCIDR checks that an input CIDR
// covered by a removed allocator stays published as in use, so that the
// operator does not release it while its IPs are in use through the removed
// allocator, e.g. when EC2 re-assigns an IP of a detached but in-use /28 as a
// /32. It never becomes allocatable, does not change the counts, and is
// dropped with its covering allocator or when it leaves the input.
func TestCIDRPoolPublishesCIDRsCoveredByRemovedCIDR(t *testing.T) {
	p0, x := delegatedPrefix(0), delegatedPrefix(1)
	host := netip.PrefixFrom(delegatedAddr(1, 4), 32)

	// setup leaves x removed and in use, with host listed.
	setup := func(t *testing.T, authoritative bool) *cidrPool {
		pool := newCIDRPool(hivetest.Logger(t), true, true)
		pool.updatePool([]netip.Prefix{p0, x}, authoritative)
		fillDelegatedPrefix(t, pool, 0, 16)
		fillDelegatedPrefix(t, pool, 1, 2)
		pool.updatePool([]netip.Prefix{p0}, authoritative)
		require.Contains(t, pool.removed, x, "precondition: %s removed", x)
		pool.updatePool([]netip.Prefix{p0, host}, authoritative)
		return pool
	}
	requirePublished := func(t *testing.T, pool *cidrPool) {
		t.Helper()
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(p0), iputil.PrefixFrom(x), iputil.PrefixFrom(host)},
			pool.inUseCIDRs(), cidrPoolState(pool))
		_, used, free, numCIDRs, _ := pool.dump()
		require.Equal(t, 18, used)
		require.Equal(t, 0, free)
		require.Equal(t, 2, numCIDRs)
		require.False(t, pool.hasAvailableIPs(), cidrPoolState(pool))
		_, err := pool.allocateNext()
		require.ErrorIs(t, err, errAllCIDRsExhausted, cidrPoolState(pool))
		requireNoOverlap(t, pool)
	}

	t.Run("published while covered", func(t *testing.T) {
		pool := setup(t, true)
		requirePublished(t, pool)
		pool.releaseExcessCIDRsMultiPool(8)
		pool.updatePool([]netip.Prefix{p0, host}, true)
		requirePublished(t, pool)
	})

	t.Run("dropped when it leaves the input", func(t *testing.T) {
		pool := setup(t, true)
		pool.updatePool([]netip.Prefix{p0}, true)
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(p0), iputil.PrefixFrom(x)}, pool.inUseCIDRs(), cidrPoolState(pool))
		require.Empty(t, pool.coveredByRemoved)
	})

	t.Run("released with its covering allocator", func(t *testing.T) {
		pool := setup(t, true)
		pool.release(delegatedAddr(1, 0))
		pool.release(delegatedAddr(1, 1))

		pool.releaseExcessCIDRsMultiPool(0)
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(p0)}, pool.inUseCIDRs(), cidrPoolState(pool))
		require.Contains(t, pool.released, host, cidrPoolState(pool))
		require.Equal(t, 0, pool.capacity())

		// The operator still lists host: it is regained, and reclaimed
		// once demand rises.
		pool.updatePool([]netip.Prefix{p0, host}, true)
		require.NotContains(t, pool.removed, host, cidrPoolState(pool))
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(p0)}, pool.inUseCIDRs(), cidrPoolState(pool))
		pool.releaseExcessCIDRsMultiPool(1)
		addr, err := pool.allocateNext()
		require.NoError(t, err, cidrPoolState(pool))
		require.Equal(t, host.Addr(), addr)
	})

	t.Run("released when updatePool drops its covering allocator", func(t *testing.T) {
		pool := setup(t, true)
		pool.release(delegatedAddr(1, 0))
		pool.release(delegatedAddr(1, 1))

		pool.updatePool([]netip.Prefix{p0, host}, true)
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(p0)}, pool.inUseCIDRs(), cidrPoolState(pool))
		require.Contains(t, pool.released, host, cidrPoolState(pool))
		require.Equal(t, 0, pool.capacity())
	})

	t.Run("generic echo does not make it allocatable", func(t *testing.T) {
		pool := setup(t, false)
		pool.updatePool(genericEcho(pool, p0), false)
		requirePublished(t, pool)

		pool.release(delegatedAddr(1, 0))
		pool.release(delegatedAddr(1, 1))
		echo := genericEcho(pool, p0)
		for _, needed := range []int{0, 1, 8} {
			pool.releaseExcessCIDRsMultiPool(needed)
			pool.updatePool(echo, false)
			require.False(t, pool.hasAvailableIPs(), "%s must not be allocatable; %s", host, cidrPoolState(pool))
		}
		require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(p0)}, pool.inUseCIDRs(), cidrPoolState(pool))

		// Once the echo is gone, the marks go away.
		pool.updatePool([]netip.Prefix{p0}, false)
		require.Empty(t, pool.removed, cidrPoolState(pool))
		require.Empty(t, pool.released, cidrPoolState(pool))
	})
}

// BenchmarkCIDRPoolHostPrefixes measures the pool operations of the agent's
// sync loop on a node with many secondary IPs, i.e. /32 allocators. They must
// scale linearly with the number of allocators (compare n=250 and n=750),
// including building the pool from scratch, which checks every new CIDR for
// overlaps with the existing allocators.
func BenchmarkCIDRPoolHostPrefixes(b *testing.B) {
	for _, n := range []int{250, 750} {
		prefixes := make([]netip.Prefix, 0, n)
		addr := netip.MustParseAddr("10.0.0.0")
		for range n {
			prefixes = append(prefixes, netip.PrefixFrom(addr, 32))
			addr = addr.Next()
		}
		newPool := func(b *testing.B) *cidrPool {
			pool := newCIDRPool(slog.New(slog.DiscardHandler), true, true)
			pool.updatePool(prefixes, true)
			// Most IPs are in use, as on a busy node.
			for _, p := range prefixes[:n*14/15] {
				require.NoError(b, pool.allocate(p.Addr()))
			}
			return pool
		}

		b.Run(fmt.Sprintf("n=%d/updatePool", n), func(b *testing.B) {
			pool := newPool(b)
			for b.Loop() {
				pool.updatePool(prefixes, true)
			}
		})
		b.Run(fmt.Sprintf("n=%d/updatePoolFromScratch", n), func(b *testing.B) {
			for b.Loop() {
				pool := newCIDRPool(slog.New(slog.DiscardHandler), true, true)
				pool.updatePool(prefixes, true)
			}
		})
		b.Run(fmt.Sprintf("n=%d/inUseIPCount", n), func(b *testing.B) {
			pool := newPool(b)
			for b.Loop() {
				pool.inUseIPCount()
			}
		})
		b.Run(fmt.Sprintf("n=%d/capacity", n), func(b *testing.B) {
			pool := newPool(b)
			for b.Loop() {
				pool.capacity()
			}
		})
		b.Run(fmt.Sprintf("n=%d/allocateNextRelease", n), func(b *testing.B) {
			pool := newPool(b)
			for b.Loop() {
				addr, err := pool.allocateNext()
				if err != nil {
					b.Fatal(err)
				}
				pool.release(addr)
			}
		})
		b.Run(fmt.Sprintf("n=%d/releaseExcessCIDRsMultiPool", n), func(b *testing.B) {
			pool := newPool(b)
			for b.Loop() {
				// Needs all free IPs, so nothing is released.
				pool.releaseExcessCIDRsMultiPool(n)
			}
		})
	}
}
