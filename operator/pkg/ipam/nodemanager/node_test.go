// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemanager

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/time"
)

type testNeededDef struct {
	available   int
	used        int
	preallocate int
	minallocate int
	maxallocate int
	result      int
}

type testExcessDef struct {
	available         int
	used              int
	preallocate       int
	minallocate       int
	maxabovewatermark int
	result            int
}

var neededDef = []testNeededDef{
	{0, 0, 0, 16, 0, 16},
	{0, 0, 8, 16, 0, 16},
	{0, 0, 16, 8, 0, 16},
	{0, 0, 16, 0, 0, 16},
	{8, 0, 0, 16, 0, 8},
	{8, 4, 8, 0, 0, 4},
	{8, 4, 8, 8, 0, 4},
	{8, 4, 8, 8, 6, 0},
	{8, 4, 8, 0, 8, 0},
	{4, 4, 8, 0, 8, 4},
}

var excessDef = []testExcessDef{
	{0, 0, 0, 16, 0, 0},
	{15, 0, 8, 16, 8, 0},
	{17, 0, 8, 16, 0, 1}, // 17 used, 8 pre-allocate, 16 min-allocate => 1 excess
	{20, 0, 8, 16, 4, 0}, // 20 used, 8 pre-allocate, 16 min-allocate, 4 max-above-watermark => 0 excess
	{21, 0, 8, 0, 4, 9},  // 21 used, 8 pre-allocate, 4 max-above-watermark => 9 excess
	{20, 0, 8, 20, 8, 0},
	{16, 1, 8, 16, 8, 0},
	{20, 4, 8, 17, 8, 0},
	{20, 4, 8, 0, 0, 8},
	{20, 4, 8, 0, 8, 0},
}

func TestCalculateNeededIPs(t *testing.T) {
	for _, d := range neededDef {
		result := calculateNeededIPs(d.available, d.used, d.preallocate, d.minallocate, d.maxallocate)
		require.Equal(t, d.result, result)
	}
}

func TestCalculateExcessIPs(t *testing.T) {
	for _, d := range excessDef {
		result := calculateExcessIPs(d.available, d.used, d.preallocate, d.minallocate, d.maxabovewatermark)
		require.Equal(t, d.result, result)
	}
}

type k8sMockNode struct{}

func (k *k8sMockNode) Update(origNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error) {
	return nil, k8sErrors.NewNotFound(v2.Resource("ciliumnodes"), newNode.Name)
}

func (k *k8sMockNode) UpdateStatus(origNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error) {
	return nil, k8sErrors.NewNotFound(v2.Resource("ciliumnodes"), newNode.Name)
}

func (k *k8sMockNode) Get(node string) (*v2.CiliumNode, error) {
	return nil, k8sErrors.NewNotFound(v2.Resource("ciliumnodes"), node)
}

func (k *k8sMockNode) Create(*v2.CiliumNode) (*v2.CiliumNode, error) {
	return &v2.CiliumNode{}, nil
}

func TestSyncToAPIServerForNonExistingNode(t *testing.T) {
	node := &Node{
		rootLogger: hivetest.Logger(t),
		name:       "test-node",
		manager: &NodeManager{
			k8sAPI: &k8sMockNode{},
		},
		logLimiter: logging.NewLimiter(10*time.Second, 3), // 1 log / 10 secs, burst of 3
		ipv4Alloc: ipAllocAttrs{
			ipsMarkedForRelease: make(map[netip.Addr]time.Time),
			ipReleaseStatus:     make(map[netip.Addr]string),
		},
		resource: newCiliumNode("test-node", 0, 0, 0),
		ops:      &nodeOperationsMock{},
	}
	node.updateLogger()

	require.NoError(t, node.syncToAPIServer())
}

func waitingForPoolMaintenance(n *Node) bool {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return n.waitingForPoolMaintenance
}

// newMaintenanceTestNode returns a node in deficit, wired with the bare
// minimum for MaintainIPPool's early returns. It deliberately has no triggers
// so that nothing runs pool maintenance concurrently with the test.
func newMaintenanceTestNode(t *testing.T, instancesAPIReady bool) *Node {
	t.Helper()

	node := &Node{
		rootLogger: hivetest.Logger(t),
		name:       "test-node",
		manager: &NodeManager{
			k8sAPI:             &k8sMockNode{},
			stableInstancesAPI: instancesAPIReady,
		},
		logLimiter: logging.NewLimiter(10*time.Second, 3), // 1 log / 10 secs, burst of 3
		resource:   newCiliumNode("test-node", 0, 0, 0),
		ops:        &nodeOperationsMock{},
	}
	node.updateLogger()
	node.stats.IPv4.NeededIPs = 1

	return node
}

// TestMaintainIPPoolReleasesPoolMaintenance covers the invariant documented on
// MaintainIPPool: it owns waitingForPoolMaintenance and releases it on every
// return path, including the early ones. The flag gates allocationNeeded() and
// releaseNeeded(), which in turn gate the only two places that ever enqueue the
// pool maintainer, so a pass that returns with the flag still set strands the
// node for good.
func TestMaintainIPPoolReleasesPoolMaintenance(t *testing.T) {
	t.Run("instances API is unstable", func(t *testing.T) {
		node := newMaintenanceTestNode(t, false)

		err := node.MaintainIPPool(context.Background())
		require.ErrorIs(t, err, errInstancesAPIUnstable)
		require.False(t, waitingForPoolMaintenance(node), "the pass must release the flag it took")
		require.True(t, node.allocationNeeded(), "node must report its deficit again so the background resync re-drives it")
	})

	t.Run("instance stopped running", func(t *testing.T) {
		node := newMaintenanceTestNode(t, true)
		node.SetRunning(false)

		require.NoError(t, node.MaintainIPPool(context.Background()))
		require.False(t, waitingForPoolMaintenance(node), "the pass must release the flag it took")
		require.True(t, node.allocationNeeded(), "node must report its deficit again so the sign of life can re-drive it")
	})
}

// TestUpdatedResourceDoesNotSetPoolMaintenance pins the other half of that
// ownership: enqueue sites only enqueue. If they set the flag themselves, they
// reintroduce the skew where setting and clearing live in different layers and
// a return path can leak it.
func TestUpdatedResourceDoesNotSetPoolMaintenance(t *testing.T) {
	node := newMaintenanceTestNode(t, true)
	maintainer := &countingPoolMaintainer{}
	node.poolMaintainer = maintainer

	require.True(t, node.UpdatedResource(newCiliumNode("test-node", 0, 4, 0)))
	require.Equal(t, 1, maintainer.triggered, "a node in deficit must enqueue a maintenance pass")
	require.False(t, waitingForPoolMaintenance(node), "the flag belongs to the pass, not to the enqueue")
}

// countingPoolMaintainer counts enqueues without running any maintenance, so
// that the flag is only ever touched by the code under test. Unlike
// poolMaintainerMock, which only silences the maintainer, the count is the
// assertion here, so it is used from a single goroutine and left unsynchronized.
type countingPoolMaintainer struct {
	triggered int
}

func (p *countingPoolMaintainer) Trigger()  { p.triggered++ }
func (p *countingPoolMaintainer) Shutdown() {}

func TestPoolRequestedIPv4(t *testing.T) {
	t.Run("returns IPv4 demand from default pool", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
			{
				Pool:   defaults.IPAMDefaultIPPool,
				Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 24},
			},
		}
		requestedIPv4, _, ok := poolRequestedIPs(cn)
		require.True(t, ok)
		require.Equal(t, 24, requestedIPv4)
	})

	t.Run("returns IPv6 demand from default pool", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
			{
				Pool:   defaults.IPAMDefaultIPPool,
				Needed: ipamTypes.IPAMPoolDemand{IPv6Addrs: 48},
			},
		}
		_, requestedIPv6, ok := poolRequestedIPs(cn)
		require.True(t, ok)
		require.Equal(t, 48, requestedIPv6)
	})

	t.Run("returns IPv4/IPv6 demand from default pool", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
			{
				Pool: defaults.IPAMDefaultIPPool,
				Needed: ipamTypes.IPAMPoolDemand{
					IPv4Addrs: 24,
					IPv6Addrs: 48,
				},
			},
		}
		requestedIPv4, requestedIPv6, ok := poolRequestedIPs(cn)
		require.True(t, ok)
		require.Equal(t, 24, requestedIPv4)
		require.Equal(t, 48, requestedIPv6)
	})

	t.Run("returns false when no Requested entries", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		_, _, ok := poolRequestedIPs(cn)
		require.False(t, ok)
	})

	t.Run("returns false when default pool not in Requested", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
			{
				Pool:   "other-pool",
				Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 10},
			},
		}
		_, _, ok := poolRequestedIPs(cn)
		require.False(t, ok)
	})

	t.Run("returns zero demand when agent requests zero", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
			{
				Pool: defaults.IPAMDefaultIPPool,
				Needed: ipamTypes.IPAMPoolDemand{
					IPv4Addrs: 0,
					IPv6Addrs: 0,
				},
			},
		}
		requestedIPv4, requestedIPv6, ok := poolRequestedIPs(cn)
		require.True(t, ok)
		require.Equal(t, 0, requestedIPv4)
		require.Equal(t, 0, requestedIPv6)
	})
}

// newMultiPoolNode creates a Node with a CiliumNode that passes the multi-pool
// heuristic (Pools.Requested present, Status.IPAM.Used empty). The enis map
// is converted to the attached CIDRs returned by ops.GetAttachedCIDRs.
func newMultiPoolNode(t *testing.T, allocated []ipamTypes.IPAMPoolAllocation, enis map[string]awsTypes.ENI) *Node {
	cn := &v2.CiliumNode{}
	cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
		{Pool: defaults.IPAMDefaultIPPool, Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 16}},
	}
	cn.Spec.IPAM.Pools.Allocated = allocated
	n := &Node{
		rootLogger:                     hivetest.Logger(t),
		resource:                       cn,
		ops:                            &nodeOperationsMock{attachedCIDRs: enisToCIDRs(enis)},
		multiPoolCIDRsMarkedForRelease: make(map[netip.Prefix]time.Time),
	}
	n.logger.Store(n.rootLogger)
	return n
}

// enisToCIDRs flattens a map of ENIs into the CIDRs (addresses as /32,
// plus prefixes) attached to them.
func enisToCIDRs(enis map[string]awsTypes.ENI) []netip.Prefix {
	if enis == nil {
		return nil
	}
	var out []netip.Prefix
	for _, eni := range enis {
		for _, prefix := range eni.Prefixes {
			if prefix.IsValid() {
				out = append(out, prefix.Prefix)
			}
		}
		for _, addr := range eni.Addresses {
			if addr.IsValid() {
				out = append(out, netip.PrefixFrom(addr.Addr, addr.BitLen()))
			}
		}
	}
	return out
}

// newPoolDemandNode returns a node whose agent uses the multi-pool allocator
// and requests the given number of addresses from the default pool. The node
// has no IPv4 addresses or IPv6 prefixes available yet.
func newPoolDemandNode(t *testing.T, requestedIPv4, requestedIPv6 int) *Node {
	t.Helper()

	cn := newCiliumNode("test-node", 8, 16, 0)
	cn.Spec.IPAM.MaxAboveWatermark = 4
	cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
		{
			Pool: defaults.IPAMDefaultIPPool,
			Needed: ipamTypes.IPAMPoolDemand{
				IPv4Addrs: requestedIPv4,
				IPv6Addrs: requestedIPv6,
			},
		},
	}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		name:       "test-node",
		manager:    &NodeManager{releaseExcessIPs: true},
		logLimiter: logging.NewLimiter(10*time.Second, 3), // 1 log / 10 secs, burst of 3
		resource:   cn,
		ops:        &nodeOperationsMock{allocator: newAllocationImplementationMock()},
	}
	n.updateLogger()
	return n
}

func TestRecalculateIPv6Only(t *testing.T) {
	t.Run("IPv6-only node needs no IPv4 addresses", func(t *testing.T) {
		n := newPoolDemandNode(t, 0, 8)
		n.recalculate(t.Context())

		stats := n.Stats()
		require.Zero(t, stats.IPv4.NeededIPs, "pre-allocate and min-allocate must not apply to IPv4")
		require.Zero(t, stats.IPv4.ExcessIPs)
		require.Equal(t, 1, stats.IPv6.NeededPrefixes)
		require.True(t, n.allocationNeeded())
	})

	t.Run("dual-stack node still pre-allocates IPv4", func(t *testing.T) {
		n := newPoolDemandNode(t, 8, 8)
		n.recalculate(t.Context())

		stats := n.Stats()
		require.Equal(t, 16, stats.IPv4.NeededIPs, "min-allocate must apply to IPv4")
		require.Equal(t, 1, stats.IPv6.NeededPrefixes)
	})

	t.Run("IPv4-only request is not IPv6-only", func(t *testing.T) {
		n := newPoolDemandNode(t, 8, 0)
		n.recalculate(t.Context())

		stats := n.Stats()
		require.Equal(t, 16, stats.IPv4.NeededIPs)
		require.Zero(t, stats.IPv6.NeededPrefixes)
	})

	t.Run("CRD allocator node is not IPv6-only", func(t *testing.T) {
		// Status.IPAM.Used being populated means the agent still uses
		// the CRD allocator, whatever Pools.Requested contains.
		n := newPoolDemandNode(t, 0, 8)
		n.resource.Status.IPAM.Used[iputil.AddrFrom(netip.MustParseAddr("10.0.0.1"))] = ipamTypes.AllocationIP{Owner: "pod"}
		n.recalculate(t.Context())

		require.Equal(t, 16, n.Stats().IPv4.NeededIPs)
	})
}

func TestRecalculateAvailableIPs(t *testing.T) {
	t.Run("every IPv4 address of attached CIDRs is counted", func(t *testing.T) {
		n := newPoolDemandNode(t, 8, 0)
		n.ops.(*nodeOperationsMock).attachedCIDRs = []netip.Prefix{
			netip.MustParsePrefix("10.0.0.1/32"),
			netip.MustParsePrefix("10.0.0.16/28"),
			netip.MustParsePrefix("2001:db8::/80"),
		}
		n.recalculate(t.Context())

		require.Equal(t, 17, n.Stats().IPv4.AvailableIPs)
	})

	t.Run("allocation map is counted when no attached CIDRs are reported", func(t *testing.T) {
		n := newPoolDemandNode(t, 8, 0)
		n.ops.(*nodeOperationsMock).allocatedIPs = []string{"10.0.0.1", "10.0.0.2"}
		n.recalculate(t.Context())

		require.Equal(t, 2, n.Stats().IPv4.AvailableIPs)
	})
}

func TestDetermineMaintenanceActionIPv6Only(t *testing.T) {
	t.Run("IPv6-only node allocates no IPv4 addresses", func(t *testing.T) {
		n := newPoolDemandNode(t, 0, 8)
		n.recalculate(t.Context())

		a, err := n.determineMaintenanceAction()
		require.NoError(t, err)
		require.NotNil(t, a)
		require.NotNil(t, a.allocation)
		require.Zero(t, a.allocation.IPv4.MaxIPsToAllocate, "max-above-watermark and surge must not apply to IPv4")
		require.Equal(t, 1, a.allocation.IPv6.MaxPrefixesToAllocate)
	})

	t.Run("dual-stack node allocates IPv4 up to the watermark", func(t *testing.T) {
		n := newPoolDemandNode(t, 8, 8)
		n.recalculate(t.Context())

		a, err := n.determineMaintenanceAction()
		require.NoError(t, err)
		require.NotNil(t, a)
		require.NotNil(t, a.allocation)
		require.Equal(t, 16+4, a.allocation.IPv4.MaxIPsToAllocate)
		require.Equal(t, 1, a.allocation.IPv6.MaxPrefixesToAllocate)
	})
}

func TestTrackMultiPoolAllocatedLocked(t *testing.T) {
	t.Run("no-op for non-multi-pool node", func(t *testing.T) {
		n := &Node{
			resource:                       &v2.CiliumNode{},
			multiPoolCIDRsMarkedForRelease: make(map[netip.Prefix]time.Time),
		}
		// No Pools.Requested -> not multi-pool.
		n.trackMultiPoolAllocatedLocked()
		require.Nil(t, n.previousAllocatedCIDRs)
	})

	t.Run("seed with no ENI orphans does not mark release", func(t *testing.T) {
		n := newMultiPoolNode(t, []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")),
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.2/32")),
			}},
		}, nil)

		n.trackMultiPoolAllocatedLocked()

		require.NotNil(t, n.previousAllocatedCIDRs)
		require.True(t, n.previousAllocatedCIDRs.Has(netip.MustParsePrefix("10.0.0.1/32")))
		require.True(t, n.previousAllocatedCIDRs.Has(netip.MustParsePrefix("10.0.0.2/32")))
		require.Empty(t, n.multiPoolCIDRsMarkedForRelease)
	})

	t.Run("removed CIDR is marked for release", func(t *testing.T) {
		enis := map[string]awsTypes.ENI{
			"eni-1": {Addresses: []iputil.Addr{
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
			}},
		}
		n := newMultiPoolNode(t, []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")),
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.2/32")),
			}},
		}, enis)

		// First call: seed.
		n.trackMultiPoolAllocatedLocked()

		// Agent removes 10.0.0.2/32 from Allocated.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")),
			}},
		}
		n.trackMultiPoolAllocatedLocked()

		require.Len(t, n.multiPoolCIDRsMarkedForRelease, 1)
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, netip.MustParsePrefix("10.0.0.2/32"))
	})

	t.Run("reappearing CIDR is removed from marked-for-release", func(t *testing.T) {
		enis := map[string]awsTypes.ENI{
			"eni-1": {Addresses: []iputil.Addr{
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
			}},
		}
		n := newMultiPoolNode(t, []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")),
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.2/32")),
			}},
		}, enis)

		// First call: seed.
		n.trackMultiPoolAllocatedLocked()

		// Remove 10.0.0.2/32.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32"))}},
		}
		n.trackMultiPoolAllocatedLocked()
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, netip.MustParsePrefix("10.0.0.2/32"))

		// Agent re-adds 10.0.0.2/32.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")),
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.2/32")),
			}},
		}
		n.trackMultiPoolAllocatedLocked()
		require.Empty(t, n.multiPoolCIDRsMarkedForRelease)
	})

	t.Run("CIDR detached from ENI is cleaned up from marked-for-release", func(t *testing.T) {
		enis := map[string]awsTypes.ENI{
			"eni-1": {Addresses: []iputil.Addr{
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
			}},
		}
		n := newMultiPoolNode(t, []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")),
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.2/32")),
			}},
		}, enis)

		// First call: seed.
		n.trackMultiPoolAllocatedLocked()

		// Agent removes 10.0.0.2/32.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32"))}},
		}
		n.trackMultiPoolAllocatedLocked()
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, netip.MustParsePrefix("10.0.0.2/32"))

		// ENI status updated: 10.0.0.2 no longer attached (operator detached it).
		n.ops.(*nodeOperationsMock).attachedCIDRs = enisToCIDRs(map[string]awsTypes.ENI{
			"eni-1": {Addresses: []iputil.Addr{
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
			}},
		})
		n.trackMultiPoolAllocatedLocked()
		require.Empty(t, n.multiPoolCIDRsMarkedForRelease)
	})

	t.Run("already-marked CIDR keeps original timestamp", func(t *testing.T) {
		enis := map[string]awsTypes.ENI{
			"eni-1": {Addresses: []iputil.Addr{
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
			}},
		}
		n := newMultiPoolNode(t, []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")),
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.2/32")),
			}},
		}, enis)

		// First call: seed.
		n.trackMultiPoolAllocatedLocked()

		// Remove 10.0.0.2/32.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32"))}},
		}
		n.trackMultiPoolAllocatedLocked()
		firstTS := n.multiPoolCIDRsMarkedForRelease[netip.MustParsePrefix("10.0.0.2/32")]

		// Call again, timestamp should not change.
		n.trackMultiPoolAllocatedLocked()
		require.Equal(t, firstTS, n.multiPoolCIDRsMarkedForRelease[netip.MustParsePrefix("10.0.0.2/32")])
	})

	t.Run("prefix delegation CIDR tracked correctly", func(t *testing.T) {
		enis := map[string]awsTypes.ENI{
			"eni-1": {
				Addresses: []iputil.Addr{
					iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
				},
				Prefixes: []iputil.Prefix{
					iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28")),
				},
			},
		}
		n := newMultiPoolNode(t, []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32")),
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28")),
			}},
		}, enis)

		// First call: seed.
		n.trackMultiPoolAllocatedLocked()

		// Agent releases the /28 prefix.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32"))}},
		}
		n.trackMultiPoolAllocatedLocked()

		require.Len(t, n.multiPoolCIDRsMarkedForRelease, 1)
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, netip.MustParsePrefix("10.0.0.16/28"))
	})
}

// multiPoolOpsMock is a focused NodeOperations mock for the
// handleMultiPoolCIDRRelease tests. It records calls and allows error
// injection. Unused methods are inherited from nodeOperationsMock as no-ops.
type multiPoolOpsMock struct {
	nodeOperationsMock

	prepare   func(released []netip.Prefix) []*ReleaseAction
	releaseFn func(*ReleaseAction) ([]netip.Prefix, error)

	prepareCalls [][]netip.Prefix
	releaseCalls []*ReleaseAction
}

func (m *multiPoolOpsMock) PrepareCIDRRelease(released []netip.Prefix) []*ReleaseAction {
	m.prepareCalls = append(m.prepareCalls, append([]netip.Prefix(nil), released...))
	if m.prepare != nil {
		return m.prepare(released)
	}
	return nil
}

func (m *multiPoolOpsMock) ReleaseCIDRs(_ context.Context, action *ReleaseAction) ([]netip.Prefix, error) {
	m.releaseCalls = append(m.releaseCalls, snapshotAction(action))
	if m.releaseFn != nil {
		return m.releaseFn(action)
	}
	return append([]netip.Prefix(nil), action.CIDRsToRelease...), nil
}

func snapshotAction(a *ReleaseAction) *ReleaseAction {
	c := *a
	c.CIDRsToRelease = append([]netip.Prefix(nil), a.CIDRsToRelease...)
	return &c
}

// k8sGetterMock returns get's result from Get and GetWithContext. The other
// methods behave like k8sMockNode.
type k8sGetterMock struct {
	k8sMockNode
	get func(ctx context.Context, name string) (*v2.CiliumNode, error)
}

func (k *k8sGetterMock) Get(name string) (*v2.CiliumNode, error) {
	return k.get(context.Background(), name)
}

func (k *k8sGetterMock) GetWithContext(ctx context.Context, name string) (*v2.CiliumNode, error) {
	return k.get(ctx, name)
}

func TestHandleMultiPoolCIDRRelease(t *testing.T) {
	setupNode := func(t *testing.T, mock *multiPoolOpsMock, marked map[netip.Prefix]time.Time, multiPool bool) *Node {
		n := &Node{
			rootLogger:                     hivetest.Logger(t),
			name:                           "test-node",
			ops:                            mock,
			excessIPReleaseDelay:           5 * time.Second,
			multiPoolCIDRsMarkedForRelease: marked,
			stats:                          Statistics{IPv4: IPStatistics{ExcessIPs: 1 << 16}},
		}
		n.logger.Store(n.rootLogger)
		cn := &v2.CiliumNode{}
		if multiPool {
			cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
				{Pool: defaults.IPAMDefaultIPPool, Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 16}},
			}
		}
		n.resource = cn
		// By default the apiserver copy matches the informer copy.
		n.manager = &NodeManager{k8sAPI: &k8sGetterMock{get: func(context.Context, string) (*v2.CiliumNode, error) {
			n.mutex.RLock()
			defer n.mutex.RUnlock()
			return n.resource.DeepCopy(), nil
		}}}
		return n
	}

	past := func() time.Time { return time.Now().Add(-time.Hour) }

	t.Run("no-op for non-multi-pool node", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{
			netip.MustParsePrefix("10.0.0.1/32"): past(),
		}, false)

		mutated, err := n.handleMultiPoolCIDRRelease(context.Background())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.prepareCalls)
	})

	t.Run("no-op when marked map is empty", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{}, true)

		mutated, err := n.handleMultiPoolCIDRRelease(context.Background())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.prepareCalls)
	})

	t.Run("no-op when delay has not elapsed", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{
			netip.MustParsePrefix("10.0.0.1/32"): time.Now(),
		}, true)

		mutated, err := n.handleMultiPoolCIDRRelease(context.Background())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.prepareCalls)
	})

	t.Run("no-op when PrepareCIDRRelease returns no actions", func(t *testing.T) {
		cidr := netip.MustParsePrefix("10.0.0.5/32")
		mock := &multiPoolOpsMock{
			prepare: func([]netip.Prefix) []*ReleaseAction { return nil },
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{cidr: past()}, true)

		mutated, err := n.handleMultiPoolCIDRRelease(context.Background())
		require.NoError(t, err)
		require.False(t, mutated)
		// CIDR still tracked so the operator will retry on the next pass.
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, cidr)
	})

	t.Run("releases single IPs and clears them from the marked map", func(t *testing.T) {
		cidr := netip.MustParsePrefix("10.0.0.5/32")
		mock := &multiPoolOpsMock{
			prepare: func([]netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{{
					InterfaceID:    "eni-1",
					CIDRsToRelease: []netip.Prefix{cidr},
				}}
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{cidr: past()}, true)

		mutated, err := n.handleMultiPoolCIDRRelease(context.Background())
		require.NoError(t, err)
		require.True(t, mutated)
		require.Len(t, mock.releaseCalls, 1)
		require.Equal(t, []netip.Prefix{cidr}, mock.releaseCalls[0].CIDRsToRelease)
		require.Empty(t, n.multiPoolCIDRsMarkedForRelease)
	})

	t.Run("releases prefixes and clears them from the marked map", func(t *testing.T) {
		cidr := netip.MustParsePrefix("10.0.0.16/28")
		mock := &multiPoolOpsMock{
			prepare: func([]netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{{
					InterfaceID:    "eni-1",
					CIDRsToRelease: []netip.Prefix{cidr},
				}}
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{cidr: past()}, true)

		mutated, err := n.handleMultiPoolCIDRRelease(context.Background())
		require.NoError(t, err)
		require.True(t, mutated)
		require.Len(t, mock.releaseCalls, 1)
		require.Equal(t, []netip.Prefix{cidr}, mock.releaseCalls[0].CIDRsToRelease)
		require.Empty(t, n.multiPoolCIDRsMarkedForRelease)
	})

	t.Run("only CIDRs past the delay are selected", func(t *testing.T) {
		ready := netip.MustParsePrefix("10.0.0.5/32")
		notReady := netip.MustParsePrefix("10.0.0.6/32")
		mock := &multiPoolOpsMock{
			prepare: func(released []netip.Prefix) []*ReleaseAction {
				require.Equal(t, []netip.Prefix{ready}, released)
				return []*ReleaseAction{{
					InterfaceID:    "eni-1",
					CIDRsToRelease: []netip.Prefix{ready},
				}}
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{
			ready:    past(),
			notReady: time.Now(),
		}, true)

		mutated, err := n.handleMultiPoolCIDRRelease(context.Background())
		require.NoError(t, err)
		require.True(t, mutated)
		require.NotContains(t, n.multiPoolCIDRsMarkedForRelease, ready)
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, notReady)
	})

	t.Run("re-check filters out CIDRs re-added between selection and release", func(t *testing.T) {
		// Both CIDRs are past the delay. Mid-PrepareCIDRRelease, simulate
		// trackMultiPoolAllocatedLocked observing the agent re-adding `readd`
		// by deleting it from the marked map. The re-check inside
		// handleMultiPoolCIDRRelease must drop it from the EC2 call.
		keep := netip.MustParsePrefix("10.0.0.16/28")
		readd := netip.MustParsePrefix("10.0.0.32/28")
		var n *Node
		mock := &multiPoolOpsMock{
			prepare: func([]netip.Prefix) []*ReleaseAction {
				n.mutex.Lock()
				delete(n.multiPoolCIDRsMarkedForRelease, readd)
				n.mutex.Unlock()
				return []*ReleaseAction{{
					InterfaceID:    "eni-1",
					CIDRsToRelease: []netip.Prefix{keep, readd},
				}}
			},
		}
		n = setupNode(t, mock, map[netip.Prefix]time.Time{
			keep:  past(),
			readd: past(),
		}, true)

		mutated, err := n.handleMultiPoolCIDRRelease(context.Background())
		require.NoError(t, err)
		require.True(t, mutated)
		require.Len(t, mock.releaseCalls, 1)
		require.Equal(t, []netip.Prefix{keep}, mock.releaseCalls[0].CIDRsToRelease)
		require.NotContains(t, n.multiPoolCIDRsMarkedForRelease, keep)
		require.NotContains(t, n.multiPoolCIDRsMarkedForRelease, readd)
	})

	t.Run("CIDR re-listed in the apiserver copy is not released", func(t *testing.T) {
		// The informer copy still lacks `readd`, but the agent has already
		// re-listed it in Spec.IPAM.Pools.Allocated (issue #47910). The GET
		// right before the EC2 call must catch this.
		keep := netip.MustParsePrefix("10.0.0.16/28")
		readd := netip.MustParsePrefix("10.0.0.32/28")
		mock := &multiPoolOpsMock{
			prepare: func([]netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{{
					InterfaceID:    "eni-1",
					CIDRsToRelease: []netip.Prefix{keep, readd},
				}}
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{
			keep:  past(),
			readd: past(),
		}, true)
		var gets int
		n.manager.k8sAPI = &k8sGetterMock{get: func(ctx context.Context, name string) (*v2.CiliumNode, error) {
			gets++
			require.Equal(t, "test-node", name)
			// The GET is bounded, so a hung apiserver cannot stall the
			// maintenance of the node.
			deadline, ok := ctx.Deadline()
			require.True(t, ok, "GET must have a deadline")
			require.WithinDuration(t, time.Now().Add(multiPoolRefreshTimeout), deadline, multiPoolRefreshTimeout)
			n.mutex.RLock()
			fresh := n.resource.DeepCopy()
			n.mutex.RUnlock()
			fresh.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
				{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{iputil.PrefixFrom(readd)}},
			}
			return fresh, nil
		}}

		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.True(t, mutated)
		require.Len(t, mock.releaseCalls, 1)
		require.Equal(t, []netip.Prefix{keep}, mock.releaseCalls[0].CIDRsToRelease)
		require.Equal(t, 1, gets)
		require.NotContains(t, n.multiPoolCIDRsMarkedForRelease, keep)
		require.NotContains(t, n.multiPoolCIDRsMarkedForRelease, readd)
	})

	t.Run("CiliumNode GET error skips the release", func(t *testing.T) {
		cidr := netip.MustParsePrefix("10.0.0.16/28")
		mock := &multiPoolOpsMock{
			prepare: func([]netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{{
					InterfaceID:    "eni-1",
					CIDRsToRelease: []netip.Prefix{cidr},
				}}
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{cidr: past()}, true)
		n.manager.k8sAPI = &k8sGetterMock{get: func(context.Context, string) (*v2.CiliumNode, error) {
			return nil, errors.New("apiserver unavailable")
		}}

		// Repeated failures are rate-limited in the log, and none releases.
		for range 5 {
			mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
			require.NoError(t, err)
			require.False(t, mutated)
		}
		require.Empty(t, mock.releaseCalls)
		// Still marked, so a later pass retries.
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, cidr)
	})

	t.Run("one CiliumNode GET per release pass", func(t *testing.T) {
		cidr1 := netip.MustParsePrefix("10.0.0.16/28")
		cidr2 := netip.MustParsePrefix("10.0.1.16/28")
		mock := &multiPoolOpsMock{
			prepare: func([]netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{
					{InterfaceID: "eni-1", CIDRsToRelease: []netip.Prefix{cidr1}},
					{InterfaceID: "eni-2", CIDRsToRelease: []netip.Prefix{cidr2}},
				}
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{
			cidr1: past(),
			cidr2: past(),
		}, true)
		var gets int
		n.manager.k8sAPI = &k8sGetterMock{get: func(context.Context, string) (*v2.CiliumNode, error) {
			gets++
			return &v2.CiliumNode{}, nil
		}}

		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.True(t, mutated)
		require.Len(t, mock.releaseCalls, 2)
		require.Equal(t, 1, gets)
	})

	t.Run("k8s API without context support is used as is", func(t *testing.T) {
		cidr := netip.MustParsePrefix("10.0.0.16/28")
		mock := &multiPoolOpsMock{
			prepare: func([]netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{{InterfaceID: "eni-1", CIDRsToRelease: []netip.Prefix{cidr}}}
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{cidr: past()}, true)
		// k8sMockNode.Get returns NotFound: the pass is skipped.
		n.manager.k8sAPI = &k8sMockNode{}

		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.releaseCalls)
	})

	t.Run("ReleaseCIDRs error preserves unreleased CIDRs in marked map", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.16/28")
		ip := netip.MustParsePrefix("10.0.0.5/32")
		mock := &multiPoolOpsMock{
			prepare: func([]netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{{
					InterfaceID:    "eni-1",
					CIDRsToRelease: []netip.Prefix{prefix, ip},
				}}
			},
			releaseFn: func(*ReleaseAction) ([]netip.Prefix, error) {
				return nil, errors.New("ec2 boom")
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{
			prefix: past(),
			ip:     past(),
		}, true)

		mutated, err := n.handleMultiPoolCIDRRelease(context.Background())
		require.Error(t, err)
		require.False(t, mutated)
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, prefix)
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, ip)
	})

	t.Run("partial release on error clears only the released subset", func(t *testing.T) {
		prefix := netip.MustParsePrefix("10.0.0.16/28")
		ip := netip.MustParsePrefix("10.0.0.5/32")
		mock := &multiPoolOpsMock{
			prepare: func([]netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{{
					InterfaceID:    "eni-1",
					CIDRsToRelease: []netip.Prefix{prefix, ip},
				}}
			},
			releaseFn: func(*ReleaseAction) ([]netip.Prefix, error) {
				return []netip.Prefix{prefix}, errors.New("ec2 boom")
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{
			prefix: past(),
			ip:     past(),
		}, true)

		mutated, err := n.handleMultiPoolCIDRRelease(context.Background())
		require.Error(t, err)
		require.True(t, mutated)
		require.NotContains(t, n.multiPoolCIDRsMarkedForRelease, prefix)
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, ip)
	})

	t.Run("multiple actions across ENIs each clear their own entries", func(t *testing.T) {
		cidr1 := netip.MustParsePrefix("10.0.0.5/32")
		cidr2 := netip.MustParsePrefix("10.0.1.5/32")
		mock := &multiPoolOpsMock{
			prepare: func([]netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{
					{InterfaceID: "eni-1", CIDRsToRelease: []netip.Prefix{cidr1}},
					{InterfaceID: "eni-2", CIDRsToRelease: []netip.Prefix{cidr2}},
				}
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{
			cidr1: past(),
			cidr2: past(),
		}, true)

		mutated, err := n.handleMultiPoolCIDRRelease(context.Background())
		require.NoError(t, err)
		require.True(t, mutated)
		require.Len(t, mock.releaseCalls, 2)
		require.Empty(t, n.multiPoolCIDRsMarkedForRelease)
	})

	t.Run("does not release below min-allocate", func(t *testing.T) {
		const (
			available   = 28
			used        = 4
			preAllocate = 1
			minAllocate = 20
		)
		var marked []netip.Prefix
		for i := used; i < available; i++ {
			marked = append(marked, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(10 + i)}), 32))
		}
		mock := &multiPoolOpsMock{
			prepare: func(released []netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{{
					InterfaceID:    "eni-1",
					CIDRsToRelease: slices.Clone(released),
				}}
			},
		}
		markedMap := make(map[netip.Prefix]time.Time, len(marked))
		for _, cidr := range marked {
			markedMap[cidr] = past()
		}
		n := setupNode(t, mock, markedMap, true)
		n.stats.IPv4.ExcessIPs = calculateExcessIPs(available, used, preAllocate, minAllocate, 0)

		_, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)

		releasedCount := 0
		for _, call := range mock.releaseCalls {
			releasedCount += len(call.CIDRsToRelease)
		}
		require.Equal(t, available-minAllocate, releasedCount)
		require.Len(t, n.multiPoolCIDRsMarkedForRelease, len(marked)-(available-minAllocate))
	})

	t.Run("waits for resync before releasing", func(t *testing.T) {
		mock := &multiPoolOpsMock{
			prepare: func(released []netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{{InterfaceID: "eni-1", CIDRsToRelease: slices.Clone(released)}}
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{
			netip.MustParsePrefix("10.0.0.1/32"): past(),
		}, true)
		n.resyncNeeded = time.Now()

		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.releaseCalls)
		require.Len(t, n.multiPoolCIDRsMarkedForRelease, 1)
	})

	t.Run("failed release requires resync", func(t *testing.T) {
		mock := &multiPoolOpsMock{
			prepare: func(released []netip.Prefix) []*ReleaseAction {
				return []*ReleaseAction{{InterfaceID: "eni-1", CIDRsToRelease: slices.Clone(released)}}
			},
			releaseFn: func(*ReleaseAction) ([]netip.Prefix, error) {
				return nil, errors.New("timeout")
			},
		}
		n := setupNode(t, mock, map[netip.Prefix]time.Time{
			netip.MustParsePrefix("10.0.0.1/32"): past(),
		}, true)

		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.Error(t, err)
		require.False(t, mutated)
		require.False(t, n.resyncNeeded.IsZero())
	})

	t.Run("releaseNeeded waits for pool maintenance and resync", func(t *testing.T) {
		n := setupNode(t, &multiPoolOpsMock{}, map[netip.Prefix]time.Time{
			netip.MustParsePrefix("10.0.0.1/32"): past(),
		}, true)
		n.manager = &NodeManager{releaseExcessIPs: true}
		require.True(t, n.releaseNeeded())

		n.waitingForPoolMaintenance = true
		require.False(t, n.releaseNeeded())

		n.waitingForPoolMaintenance = false
		n.resyncNeeded = time.Now()
		require.False(t, n.releaseNeeded())

		n.updateLastResync(time.Now().Add(time.Second))
		require.True(t, n.releaseNeeded())
	})
}

// newHandshakeNode returns a multi-pool node whose agent takes part in the
// CIDR release handshake, with x attached and released by the agent and
// marked as a release candidate at ts. GETs from the apiserver return
// fresh, if set, or a copy of the informer copy.
func newHandshakeNode(t *testing.T, mock *multiPoolOpsMock, x netip.Prefix, ts time.Time, fresh func(*v2.CiliumNode)) *Node {
	t.Helper()
	mock.attachedCIDRs = []netip.Prefix{x}
	if mock.prepare == nil {
		mock.prepare = func(cidrs []netip.Prefix) []*ReleaseAction {
			return []*ReleaseAction{{InterfaceID: "eni-1", CIDRsToRelease: slices.Clone(cidrs)}}
		}
	}
	n := &Node{
		rootLogger:                     hivetest.Logger(t),
		name:                           "test-node",
		ops:                            mock,
		excessIPReleaseDelay:           5 * time.Second,
		multiPoolCIDRsMarkedForRelease: map[netip.Prefix]time.Time{x: ts},
		stats:                          Statistics{IPv4: IPStatistics{ExcessIPs: 1 << 16}},
		logLimiter:                     logging.NewLimiter(10*time.Second, 3),
	}
	n.logger.Store(n.rootLogger)
	cn := &v2.CiliumNode{}
	cn.Name = "test-node"
	cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
		{Pool: defaults.IPAMDefaultIPPool, Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 16}},
	}
	cn.Spec.IPAM.CIDRReleaseHandshake = true
	n.resource = cn
	n.manager = &NodeManager{k8sAPI: &k8sGetterMock{get: func(context.Context, string) (*v2.CiliumNode, error) {
		n.mutex.RLock()
		node := n.resource.DeepCopy()
		n.mutex.RUnlock()
		if fresh != nil {
			fresh(node)
		}
		return node, nil
	}}}
	return n
}

// agentAnswers sets the agent's answer for x in the informer copy.
func agentAnswers(n *Node, x netip.Prefix, status string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	if n.resource.Status.IPAM.ReleaseCIDRs == nil {
		n.resource.Status.IPAM.ReleaseCIDRs = ipamTypes.CIDRReleaseStatusMap{}
	}
	n.resource.Status.IPAM.ReleaseCIDRs[iputil.PrefixFrom(x)] = ipamTypes.IPReleaseStatus(status)
}

// publishedReleaseStatus returns the Status.IPAM.ReleaseCIDRs that the
// operator writes on top of the informer copy, and makes it the informer
// copy, as after a successful syncToAPIServer.
func publishedReleaseStatus(n *Node) ipamTypes.CIDRReleaseStatusMap {
	node := n.ResourceCopy()
	n.PopulateIPReleaseStatus(node)
	n.mutex.Lock()
	n.resource.Status.IPAM.ReleaseCIDRs = node.Status.IPAM.ReleaseCIDRs.DeepCopy()
	n.mutex.Unlock()
	return node.Status.IPAM.ReleaseCIDRs
}

func releaseStatus(x netip.Prefix, status string) ipamTypes.CIDRReleaseStatusMap {
	return ipamTypes.CIDRReleaseStatusMap{iputil.PrefixFrom(x): ipamTypes.IPReleaseStatus(status)}
}

// TestHandleMultiPoolCIDRReleaseHandshake covers the operator side of the
// multi-pool CIDR release handshake (cilium/cilium#47910).
func TestHandleMultiPoolCIDRReleaseHandshake(t *testing.T) {
	x := netip.MustParsePrefix("10.0.0.16/28")
	past := time.Now().Add(-time.Hour)

	t.Run("CIDR is marked, not released", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, past, nil)

		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.releaseCalls)
		require.Equal(t, releaseStatus(x, ipamOption.IPAMMarkForRelease), publishedReleaseStatus(n))
	})

	t.Run("no release without the agent's answer, and no timeout", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, time.Now().Add(-24*time.Hour), nil)
		for range 10 {
			mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
			require.NoError(t, err)
			require.False(t, mutated)
			publishedReleaseStatus(n)
		}
		require.Empty(t, mock.releaseCalls)
		require.Equal(t, releaseStatus(x, ipamOption.IPAMMarkForRelease), publishedReleaseStatus(n))
	})

	t.Run("ready-for-release is released, then the handshake ends", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, past, nil)
		_, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		publishedReleaseStatus(n)

		agentAnswers(n, x, ipamOption.IPAMReadyForRelease)
		// The operator keeps the agent's answer while the CIDR is marked.
		require.Equal(t, releaseStatus(x, ipamOption.IPAMReadyForRelease), publishedReleaseStatus(n))

		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.True(t, mutated)
		require.Len(t, mock.releaseCalls, 1)
		require.Equal(t, []netip.Prefix{x}, mock.releaseCalls[0].CIDRsToRelease)
		require.NotContains(t, n.multiPoolCIDRsMarkedForRelease, x)
		require.Equal(t, releaseStatus(x, ipamOption.IPAMReleased), publishedReleaseStatus(n))

		// The agent removes the released CIDR once it is gone from
		// Status.ENI, which ends the handshake.
		n.mutex.Lock()
		delete(n.resource.Status.IPAM.ReleaseCIDRs, iputil.PrefixFrom(x))
		n.mutex.Unlock()
		require.Empty(t, publishedReleaseStatus(n))
		require.Empty(t, n.multiPoolCIDRReleaseStatus)
	})

	t.Run("answer missing from the apiserver copy is not released", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, past, func(fresh *v2.CiliumNode) {
			fresh.Status.IPAM.ReleaseCIDRs = releaseStatus(x, ipamOption.IPAMMarkForRelease)
		})
		_, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		agentAnswers(n, x, ipamOption.IPAMReadyForRelease)

		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.releaseCalls)
		require.Equal(t, ipamOption.IPAMMarkForRelease, n.multiPoolCIDRReleaseStatus[x].status)
	})

	t.Run("CIDR re-listed in the apiserver copy is not released", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, past, func(fresh *v2.CiliumNode) {
			fresh.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
				{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{iputil.PrefixFrom(x)}},
			}
		})
		_, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		agentAnswers(n, x, ipamOption.IPAMReadyForRelease)

		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.releaseCalls)
		require.Empty(t, publishedReleaseStatus(n))
	})

	t.Run("do-not-release clears the mark", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, past, nil)
		_, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		agentAnswers(n, x, ipamOption.IPAMDoNotRelease)

		before := time.Now()
		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.releaseCalls)
		require.Empty(t, publishedReleaseStatus(n))
		// The delay starts over before the CIDR is marked again.
		require.False(t, n.multiPoolCIDRsMarkedForRelease[x].Before(before))
	})

	t.Run("mark is cleared when the node is no longer in excess", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, past, nil)
		_, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		agentAnswers(n, x, ipamOption.IPAMReadyForRelease)

		n.mutex.Lock()
		n.stats.IPv4.ExcessIPs = 0
		n.mutex.Unlock()
		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.releaseCalls)
		require.Empty(t, publishedReleaseStatus(n))
	})

	t.Run("agent re-listing a marked CIDR clears the mark", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, past, nil)
		n.mutex.Lock()
		n.previousAllocatedCIDRs = sets.New[netip.Prefix]()
		n.mutex.Unlock()
		_, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)

		n.mutex.Lock()
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{iputil.PrefixFrom(x)}},
		}
		n.trackMultiPoolAllocatedLocked()
		n.mutex.Unlock()
		require.Empty(t, publishedReleaseStatus(n))
	})

	t.Run("old agent without the handshake is released as before", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, past, nil)
		n.resource.Spec.IPAM.CIDRReleaseHandshake = false

		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.True(t, mutated)
		require.Len(t, mock.releaseCalls, 1)
		require.Nil(t, publishedReleaseStatus(n))
	})

	t.Run("agent downgrade drops the handshake state", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, past, nil)
		_, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, publishedReleaseStatus(n))

		n.mutex.Lock()
		n.resource.Spec.IPAM.CIDRReleaseHandshake = false
		n.mutex.Unlock()
		require.Nil(t, publishedReleaseStatus(n))
		require.Empty(t, n.multiPoolCIDRReleaseStatus)
	})

	t.Run("stale ready-for-release of a downgraded agent is not released", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, past, func(fresh *v2.CiliumNode) {
			// The downgraded agent's spec write has reached the apiserver,
			// its answer has not been cleared yet.
			fresh.Spec.IPAM.CIDRReleaseHandshake = false
		})
		_, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		agentAnswers(n, x, ipamOption.IPAMReadyForRelease)

		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.releaseCalls)
		require.Equal(t, ipamOption.IPAMMarkForRelease, n.multiPoolCIDRReleaseStatus[x].status)
	})

	t.Run("mark of a CIDR that is no longer eligible is cleared at once", func(t *testing.T) {
		eligible := true
		mock := &multiPoolOpsMock{prepare: func(cidrs []netip.Prefix) []*ReleaseAction {
			if !eligible {
				return nil
			}
			return []*ReleaseAction{{InterfaceID: "eni-1", CIDRsToRelease: slices.Clone(cidrs)}}
		}}
		n := newHandshakeNode(t, mock, x, past, nil)
		_, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.Equal(t, releaseStatus(x, ipamOption.IPAMMarkForRelease), publishedReleaseStatus(n))
		agentAnswers(n, x, ipamOption.IPAMReadyForRelease)

		// PrepareCIDRRelease no longer returns x: its delay starts over,
		// and its mark is cleared in the same pass.
		eligible = false
		_, err = n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.Empty(t, publishedReleaseStatus(n))

		// No candidate is past the delay in the next pass, and no mark is
		// left behind.
		_, err = n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.Empty(t, mock.releaseCalls)
		require.Empty(t, n.multiPoolCIDRReleaseStatus)
		require.Empty(t, publishedReleaseStatus(n))
	})
}

// TestMultiPoolCIDRReleaseHandshakeReassigned checks that the handshake of a
// released CIDR ends when the CIDR is attached again, e.g. because EC2 hands
// the just-released prefix back to the ENI before the agent has seen it go
// (cilium/cilium#47910). Otherwise the agent, which only removes a released
// CIDR once it is no longer advertised, would keep it blocked for good.
func TestMultiPoolCIDRReleaseHandshakeReassigned(t *testing.T) {
	x := netip.MustParsePrefix("10.0.0.16/28")
	past := time.Now().Add(-time.Hour)

	// released returns a node on which x has just been released, with x
	// still attached as returned by attached.
	released := func(t *testing.T, attached ...netip.Prefix) (*Node, *multiPoolOpsMock) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, past, nil)
		_, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		publishedReleaseStatus(n)
		agentAnswers(n, x, ipamOption.IPAMReadyForRelease)
		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.True(t, mutated)
		require.Equal(t, releaseStatus(x, ipamOption.IPAMReleased), publishedReleaseStatus(n))
		mock.attachedCIDRs = attached
		return n, mock
	}
	// age makes the release of x older than multiPoolReassignDelay.
	age := func(n *Node) {
		n.mutex.Lock()
		release := n.multiPoolCIDRReleaseStatus[x]
		release.releasedAt = time.Now().Add(-multiPoolReassignDelay - time.Second)
		n.multiPoolCIDRReleaseStatus[x] = release
		n.mutex.Unlock()
	}

	t.Run("re-assigned CIDR ends the handshake", func(t *testing.T) {
		n, _ := released(t, x)

		// A resync right after the release may not reflect it yet.
		n.recalculate(t.Context())
		require.Equal(t, releaseStatus(x, ipamOption.IPAMReleased), publishedReleaseStatus(n))

		age(n)
		n.recalculate(t.Context())
		require.Empty(t, n.multiPoolCIDRReleaseStatus)
		require.Empty(t, publishedReleaseStatus(n))
	})

	t.Run("detached CIDR stays released until the agent removes it", func(t *testing.T) {
		n, _ := released(t, netip.MustParsePrefix("10.0.0.32/28"))
		age(n)
		n.recalculate(t.Context())
		require.Equal(t, releaseStatus(x, ipamOption.IPAMReleased), publishedReleaseStatus(n))
	})

	t.Run("resync that started before the delay elapsed does not count", func(t *testing.T) {
		n, _ := released(t, x)
		n.mutex.Lock()
		releasedAt := n.multiPoolCIDRReleaseStatus[x].releasedAt
		require.False(t, n.clearReassignedMultiPoolCIDRsLocked([]netip.Prefix{x}, releasedAt.Add(multiPoolReassignDelay-time.Millisecond)))
		require.True(t, n.clearReassignedMultiPoolCIDRsLocked([]netip.Prefix{x}, releasedAt.Add(multiPoolReassignDelay)))
		n.mutex.Unlock()
	})

	t.Run("released CIDR adopted after a restart ends the handshake once attached", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := newHandshakeNode(t, mock, x, time.Time{}, nil)
		n.multiPoolCIDRsMarkedForRelease = map[netip.Prefix]time.Time{}
		n.resource.Status.IPAM.ReleaseCIDRs = releaseStatus(x, ipamOption.IPAMReleased)
		n.mutex.Lock()
		n.trackMultiPoolAllocatedLocked()
		n.mutex.Unlock()
		require.Equal(t, releaseStatus(x, ipamOption.IPAMReleased), publishedReleaseStatus(n))

		// Without tombstones, the first listings after the restart may be
		// stale, so the delay also applies to an adopted release.
		n.recalculate(t.Context())
		require.Equal(t, releaseStatus(x, ipamOption.IPAMReleased), publishedReleaseStatus(n))

		age(n)
		n.recalculate(t.Context())
		require.Empty(t, publishedReleaseStatus(n))
	})
}

// TestMultiPoolCIDRReleaseHandshakeOperatorRestart checks that an operator
// that restarts, or a new leader, takes over the handshake state left in
// Status.IPAM.ReleaseCIDRs (cilium/cilium#47910).
func TestMultiPoolCIDRReleaseHandshakeOperatorRestart(t *testing.T) {
	x := netip.MustParsePrefix("10.0.0.16/28")
	y := netip.MustParsePrefix("10.0.0.32/28")

	// restarted returns a fresh node whose CiliumNode carries release, with
	// x and y attached and not listed by the agent, seeded as after a
	// restart.
	restarted := func(t *testing.T, mock *multiPoolOpsMock, release ipamTypes.CIDRReleaseStatusMap) *Node {
		n := newHandshakeNode(t, mock, x, time.Time{}, nil)
		mock.attachedCIDRs = []netip.Prefix{x, y}
		n.multiPoolCIDRsMarkedForRelease = map[netip.Prefix]time.Time{}
		n.resource.Status.IPAM.ReleaseCIDRs = release
		n.mutex.Lock()
		n.trackMultiPoolAllocatedLocked()
		n.mutex.Unlock()
		return n
	}

	t.Run("acknowledged mark is kept and released after the delay", func(t *testing.T) {
		mock := &multiPoolOpsMock{}
		n := restarted(t, mock, releaseStatus(x, ipamOption.IPAMReadyForRelease))
		require.Equal(t, releaseStatus(x, ipamOption.IPAMReadyForRelease), publishedReleaseStatus(n))

		// The delay starts over after the restart.
		mutated, err := n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.False(t, mutated)
		require.Empty(t, mock.releaseCalls)

		n.mutex.Lock()
		for cidr := range n.multiPoolCIDRsMarkedForRelease {
			n.multiPoolCIDRsMarkedForRelease[cidr] = time.Now().Add(-time.Hour)
		}
		n.mutex.Unlock()
		// The first pass marks y, which has no answer yet. x is released.
		mutated, err = n.handleMultiPoolCIDRRelease(t.Context())
		require.NoError(t, err)
		require.True(t, mutated)
		require.Len(t, mock.releaseCalls, 1)
		require.Equal(t, []netip.Prefix{x}, mock.releaseCalls[0].CIDRsToRelease)
		require.Equal(t, ipamTypes.CIDRReleaseStatusMap{
			iputil.PrefixFrom(x): ipamOption.IPAMReleased,
			iputil.PrefixFrom(y): ipamOption.IPAMMarkForRelease,
		}, publishedReleaseStatus(n))
	})

	t.Run("unanswered mark is kept", func(t *testing.T) {
		n := restarted(t, &multiPoolOpsMock{}, releaseStatus(x, ipamOption.IPAMMarkForRelease))
		require.Equal(t, releaseStatus(x, ipamOption.IPAMMarkForRelease), publishedReleaseStatus(n))
	})

	t.Run("released CIDR stays released until the agent removes it", func(t *testing.T) {
		n := restarted(t, &multiPoolOpsMock{}, releaseStatus(netip.MustParsePrefix("10.0.0.48/28"), ipamOption.IPAMReleased))
		require.Equal(t, releaseStatus(netip.MustParsePrefix("10.0.0.48/28"), ipamOption.IPAMReleased), publishedReleaseStatus(n))
	})

	t.Run("refused or stale marks are dropped", func(t *testing.T) {
		n := restarted(t, &multiPoolOpsMock{}, ipamTypes.CIDRReleaseStatusMap{
			iputil.PrefixFrom(x): ipamOption.IPAMDoNotRelease,
			// Not attached any more, so not a candidate.
			iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.64/28")): ipamOption.IPAMReadyForRelease,
		})
		require.Empty(t, publishedReleaseStatus(n))
	})
}
