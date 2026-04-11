// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemanager

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/defaults"
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

func TestPoolRequestedIPv4(t *testing.T) {
	t.Run("returns demand from default pool", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
			{
				Pool:   defaults.IPAMDefaultIPPool,
				Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 24},
			},
		}
		requested, ok := poolRequestedIPv4(cn)
		require.True(t, ok)
		require.Equal(t, 24, requested)
	})

	t.Run("returns false when no Requested entries", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		_, ok := poolRequestedIPv4(cn)
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
		_, ok := poolRequestedIPv4(cn)
		require.False(t, ok)
	})

	t.Run("returns zero demand when agent requests zero", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
			{
				Pool:   defaults.IPAMDefaultIPPool,
				Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 0},
			},
		}
		requested, ok := poolRequestedIPv4(cn)
		require.True(t, ok)
		require.Equal(t, 0, requested)
	})
}

// newMultiPoolNode creates a Node with a CiliumNode that passes the multi-pool
// heuristic (Pools.Requested present, Status.IPAM.Used empty). The enis map
// is converted to the attached CIDRs returned by ops.GetAttachedCIDRs.
func newMultiPoolNode(t *testing.T, allocated []ipamTypes.IPAMPoolAllocation, enis map[string]eniTypes.ENI) *Node {
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
func enisToCIDRs(enis map[string]eniTypes.ENI) []netip.Prefix {
	if enis == nil {
		return nil
	}
	var out []netip.Prefix
	for _, eni := range enis {
		for _, prefix := range eni.Prefixes {
			if p, err := netip.ParsePrefix(prefix); err == nil {
				out = append(out, p)
			}
		}
		for _, addr := range eni.Addresses {
			if a, err := netip.ParseAddr(addr); err == nil {
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	return out
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
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32", "10.0.0.2/32"}},
		}, nil)

		n.trackMultiPoolAllocatedLocked()

		require.NotNil(t, n.previousAllocatedCIDRs)
		require.True(t, n.previousAllocatedCIDRs.Has(netip.MustParsePrefix("10.0.0.1/32")))
		require.True(t, n.previousAllocatedCIDRs.Has(netip.MustParsePrefix("10.0.0.2/32")))
		require.Empty(t, n.multiPoolCIDRsMarkedForRelease)
	})

	t.Run("removed CIDR is marked for release", func(t *testing.T) {
		enis := map[string]eniTypes.ENI{
			"eni-1": {Addresses: []string{"10.0.0.1", "10.0.0.2"}},
		}
		n := newMultiPoolNode(t, []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32", "10.0.0.2/32"}},
		}, enis)

		// First call: seed.
		n.trackMultiPoolAllocatedLocked()

		// Agent removes 10.0.0.2/32 from Allocated.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32"}},
		}
		n.trackMultiPoolAllocatedLocked()

		require.Len(t, n.multiPoolCIDRsMarkedForRelease, 1)
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, netip.MustParsePrefix("10.0.0.2/32"))
	})

	t.Run("reappearing CIDR is removed from marked-for-release", func(t *testing.T) {
		enis := map[string]eniTypes.ENI{
			"eni-1": {Addresses: []string{"10.0.0.1", "10.0.0.2"}},
		}
		n := newMultiPoolNode(t, []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32", "10.0.0.2/32"}},
		}, enis)

		// First call: seed.
		n.trackMultiPoolAllocatedLocked()

		// Remove 10.0.0.2/32.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32"}},
		}
		n.trackMultiPoolAllocatedLocked()
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, netip.MustParsePrefix("10.0.0.2/32"))

		// Agent re-adds 10.0.0.2/32.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32", "10.0.0.2/32"}},
		}
		n.trackMultiPoolAllocatedLocked()
		require.Empty(t, n.multiPoolCIDRsMarkedForRelease)
	})

	t.Run("CIDR detached from ENI is cleaned up from marked-for-release", func(t *testing.T) {
		enis := map[string]eniTypes.ENI{
			"eni-1": {Addresses: []string{"10.0.0.1", "10.0.0.2"}},
		}
		n := newMultiPoolNode(t, []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32", "10.0.0.2/32"}},
		}, enis)

		// First call: seed.
		n.trackMultiPoolAllocatedLocked()

		// Agent removes 10.0.0.2/32.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32"}},
		}
		n.trackMultiPoolAllocatedLocked()
		require.Contains(t, n.multiPoolCIDRsMarkedForRelease, netip.MustParsePrefix("10.0.0.2/32"))

		// ENI status updated: 10.0.0.2 no longer attached (operator detached it).
		n.ops.(*nodeOperationsMock).attachedCIDRs = enisToCIDRs(map[string]eniTypes.ENI{
			"eni-1": {Addresses: []string{"10.0.0.1"}},
		})
		n.trackMultiPoolAllocatedLocked()
		require.Empty(t, n.multiPoolCIDRsMarkedForRelease)
	})

	t.Run("already-marked CIDR keeps original timestamp", func(t *testing.T) {
		enis := map[string]eniTypes.ENI{
			"eni-1": {Addresses: []string{"10.0.0.1", "10.0.0.2"}},
		}
		n := newMultiPoolNode(t, []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32", "10.0.0.2/32"}},
		}, enis)

		// First call: seed.
		n.trackMultiPoolAllocatedLocked()

		// Remove 10.0.0.2/32.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32"}},
		}
		n.trackMultiPoolAllocatedLocked()
		firstTS := n.multiPoolCIDRsMarkedForRelease[netip.MustParsePrefix("10.0.0.2/32")]

		// Call again, timestamp should not change.
		n.trackMultiPoolAllocatedLocked()
		require.Equal(t, firstTS, n.multiPoolCIDRsMarkedForRelease[netip.MustParsePrefix("10.0.0.2/32")])
	})

	t.Run("prefix delegation CIDR tracked correctly", func(t *testing.T) {
		enis := map[string]eniTypes.ENI{
			"eni-1": {
				Addresses: []string{"10.0.0.1"},
				Prefixes:  []string{"10.0.0.16/28"},
			},
		}
		n := newMultiPoolNode(t, []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32", "10.0.0.16/28"}},
		}, enis)

		// First call: seed.
		n.trackMultiPoolAllocatedLocked()

		// Agent releases the /28 prefix.
		n.resource.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{Pool: defaults.IPAMDefaultIPPool, CIDRs: []ipamTypes.IPAMCIDR{"10.0.0.1/32"}},
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

func TestHandleMultiPoolCIDRRelease(t *testing.T) {
	setupNode := func(t *testing.T, mock *multiPoolOpsMock, marked map[netip.Prefix]time.Time, multiPool bool) *Node {
		n := &Node{
			rootLogger:                     hivetest.Logger(t),
			ops:                            mock,
			excessIPReleaseDelay:           5 * time.Second,
			multiPoolCIDRsMarkedForRelease: marked,
		}
		n.logger.Store(n.rootLogger)
		cn := &v2.CiliumNode{}
		if multiPool {
			cn.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
				{Pool: defaults.IPAMDefaultIPPool, Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 16}},
			}
		}
		n.resource = cn
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
}
