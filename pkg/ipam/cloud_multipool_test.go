// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"

	iputil "github.com/cilium/cilium/pkg/ip"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/mac"
)

type fakeResolver struct {
	err       error
	onResolve func()

	calls     int
	seenNode  *ciliumv2.CiliumNode
	seenAddrs []netip.Addr
	seenPools []Pool
}

func (r *fakeResolver) ResolveRoutingMetadata(node *ciliumv2.CiliumNode, addr netip.Addr, pool Pool) (*AllocationResult, error) {
	r.calls++
	r.seenNode = node
	r.seenAddrs = append(r.seenAddrs, addr)
	r.seenPools = append(r.seenPools, pool)

	if r.onResolve != nil {
		r.onResolve()
	}
	if r.err != nil {
		return nil, r.err
	}

	return &AllocationResult{
		IP:              addr,
		IPPoolName:      pool,
		PrimaryMAC:      mac.MustParseMAC("00:00:5e:00:53:01"),
		GatewayIP:       netip.MustParseAddr("10.20.30.1"),
		CIDRs:           []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")},
		InterfaceNumber: "0",
	}, nil
}

const cloudTestPool = Pool("default")

func newTestCloudMultiPoolAllocator(t *testing.T, resolver RoutingMetadataResolver, node *ciliumv2.CiliumNode) *cloudMultiPoolAllocator {
	t.Helper()

	logger := hivetest.Logger(t)
	mgr := &multiPoolManager{
		logger:            logger,
		ipv4Enabled:       true,
		pools:             map[Pool]*poolPair{},
		poolsUpdated:      make(chan struct{}, 1),
		pendingIPsPerPool: newPendingAllocationsPerPool(logger),
		k8sUpdater:        job.NewTrigger(),
		node:              node,
		skipMasqueradeForPool: func(Pool) (bool, error) {
			return false, nil
		},
	}
	mgr.upsertPoolLocked(
		cloudTestPool,
		[]iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.20.30.0/29"))},
		false,
		false,
	)

	return &cloudMultiPoolAllocator{
		multiPoolAllocator: multiPoolAllocator{manager: mgr, family: IPv4},
		resolver:           resolver,
	}
}

func inUseIPs(t *testing.T, a *cloudMultiPoolAllocator) int {
	t.Helper()

	pool, ok := a.manager.pools[cloudTestPool]
	require.True(t, ok)
	return pool.v4.inUseIPCount()
}

func TestCloudMultiPoolAllocatorEnrichesResults(t *testing.T) {
	addr := netip.MustParseAddr("10.20.30.2")

	allocations := map[string]func(a *cloudMultiPoolAllocator) (*AllocationResult, error){
		"Allocate": func(a *cloudMultiPoolAllocator) (*AllocationResult, error) {
			return a.Allocate(addr, "ns/pod", cloudTestPool)
		},
		"AllocateWithoutSyncUpstream": func(a *cloudMultiPoolAllocator) (*AllocationResult, error) {
			return a.AllocateWithoutSyncUpstream(addr, "ns/pod", cloudTestPool)
		},
		"AllocateNext": func(a *cloudMultiPoolAllocator) (*AllocationResult, error) {
			return a.AllocateNext("ns/pod", cloudTestPool)
		},
		"AllocateNextWithoutSyncUpstream": func(a *cloudMultiPoolAllocator) (*AllocationResult, error) {
			return a.AllocateNextWithoutSyncUpstream("ns/pod", cloudTestPool)
		},
	}

	for name, allocate := range allocations {
		t.Run(name, func(t *testing.T) {
			node := &ciliumv2.CiliumNode{}
			resolver := &fakeResolver{}
			a := newTestCloudMultiPoolAllocator(t, resolver, node)

			result, err := allocate(a)
			require.NoError(t, err)

			require.Equal(t, 1, resolver.calls)
			require.Same(t, node, resolver.seenNode)
			require.Equal(t, []Pool{cloudTestPool}, resolver.seenPools)

			require.Equal(t, cloudTestPool, result.IPPoolName)
			require.Equal(t, []netip.Addr{result.IP}, resolver.seenAddrs)
			require.Equal(t, mac.MustParseMAC("00:00:5e:00:53:01"), result.PrimaryMAC)
			require.Equal(t, netip.MustParseAddr("10.20.30.1"), result.GatewayIP)
			require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")}, result.CIDRs)
			require.Equal(t, "0", result.InterfaceNumber)

			require.Equal(t, 1, inUseIPs(t, a))
		})
	}
}

func TestCloudMultiPoolAllocatorReleasesOnEnrichmentFailure(t *testing.T) {
	addr := netip.MustParseAddr("10.20.30.2")
	resolveErr := errors.New("no interface carries this IP")

	resolver := &fakeResolver{err: resolveErr}
	a := newTestCloudMultiPoolAllocator(t, resolver, &ciliumv2.CiliumNode{})

	result, err := a.Allocate(addr, "ns/pod", cloudTestPool)
	require.ErrorIs(t, err, resolveErr)
	require.Nil(t, result)

	require.Zero(t, inUseIPs(t, a))

	resolver.err = nil
	result, err = a.Allocate(addr, "ns/pod", cloudTestPool)
	require.NoError(t, err)
	require.Equal(t, addr, result.IP)
}

func TestCloudMultiPoolAllocatorReportsReleaseFailure(t *testing.T) {
	addr := netip.MustParseAddr("10.20.30.2")
	resolveErr := errors.New("no interface carries this IP")

	resolver := &fakeResolver{err: resolveErr}
	a := newTestCloudMultiPoolAllocator(t, resolver, &ciliumv2.CiliumNode{})
	resolver.onResolve = func() {
		delete(a.manager.pools, cloudTestPool)
	}

	result, err := a.Allocate(addr, "ns/pod", cloudTestPool)
	require.Nil(t, result)
	require.ErrorIs(t, err, resolveErr)
	require.ErrorContains(t, err, "release after enrichment failure")
	require.ErrorContains(t, err, `unable to release IP 10.20.30.2 of unknown pool "default"`)
}

func TestCloudMultiPoolAllocatorSkipsEnrichmentOnAllocationFailure(t *testing.T) {
	resolver := &fakeResolver{}
	a := newTestCloudMultiPoolAllocator(t, resolver, &ciliumv2.CiliumNode{})

	result, err := a.Allocate(netip.MustParseAddr("10.20.40.2"), "ns/pod", cloudTestPool)
	require.Error(t, err)
	require.Nil(t, result)
	require.Zero(t, resolver.calls)

	result, err = a.AllocateNext("ns/pod", Pool("missing"))
	require.Error(t, err)
	require.Nil(t, result)
	require.Zero(t, resolver.calls)
}
