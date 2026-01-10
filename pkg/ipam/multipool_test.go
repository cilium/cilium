// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ipam/podippool"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/trigger"
)

var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second
)

func Test_MultiPoolManager(t *testing.T) {
	db := statedb.New()
	poolsTbl, err := podippool.NewTable(db)
	require.NoError(t, err)
	insertPool(t, db, poolsTbl, "default", false)
	insertPool(t, db, poolsTbl, "mars", false)
	insertPool(t, db, poolsTbl, "jupiter", false)

	fakeConfig := testConfiguration
	// set custom preAllocMap for unit tests
	fakeConfig.IPAMMultiPoolPreAllocation = map[string]string{
		"default": "16",
		"mars":    "8",
	}
	fakeOwner := &ownerMock{}
	fakeLocalNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	events := make(chan string, 1)
	cnEvents := make(chan resource.Event[*ciliumv2.CiliumNode])
	fakeK8sCiliumNodeAPI := &fakeK8sCiliumNodeAPIResource{
		c:    cnEvents,
		node: &ciliumv2.CiliumNode{},
		onDeleteEvent: func(err error) {
			if err != nil {
				t.Errorf("deleting failed: %v", err)
			}
			events <- "delete"
		},
		onUpsertEvent: func(err error) {
			if err != nil {
				t.Errorf("upserting failed: %v", err)
			}
			events <- "upsert"
		},
	}

	defaultIPv4CIDR1 := cidr.MustParseCIDR("10.0.22.0/24")
	defaultIPv6CIDR1 := cidr.MustParseCIDR("fd00:22::/96")
	marsIPv4CIDR1 := cidr.MustParseCIDR("10.0.11.0/27")
	marsIPv6CIDR1 := cidr.MustParseCIDR("fd00:11::/123")

	currentNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeTypes.GetName()},
		Spec: ciliumv2.NodeSpec{
			IPAM: types.IPAMSpec{
				Pools: types.IPAMPoolSpec{
					Allocated: []types.IPAMPoolAllocation{
						{
							Pool: "default",
							CIDRs: []types.IPAMPodCIDR{
								types.IPAMPodCIDR(defaultIPv4CIDR1.String()),
								types.IPAMPodCIDR(defaultIPv6CIDR1.String()),
							},
						},
						{
							Pool: "mars",
							CIDRs: []types.IPAMPodCIDR{
								types.IPAMPodCIDR(marsIPv4CIDR1.String()),
								types.IPAMPodCIDR(marsIPv6CIDR1.String()),
							},
						},
					},
				},
			},
		},
	}

	// provide initial CiliumNode CRD - we expect newMultiPoolManager to stop
	// waiting for initial local node sync and return
	go fakeK8sCiliumNodeAPI.updateNode(currentNode)

	c := newMultiPoolManager(MultiPoolManagerParams{
		Logger:         hivetest.Logger(t),
		Conf:           fakeConfig,
		Node:           fakeK8sCiliumNodeAPI,
		Owner:          fakeOwner,
		LocalNodeStore: fakeLocalNodeStore,
		Clientset:      fakeK8sCiliumNodeAPI,
		DB:             db,
		PodIPPools:     poolsTbl,
	})

	// For testing, we want every trigger to run the controller once
	k8sUpdater, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: 0,
		TriggerFunc: func(reasons []string) {
			c.controller.TriggerController(multiPoolControllerName)
		},
		Name: multiPoolTriggerName,
	})
	assert.NoError(t, err)
	c.k8sUpdater = k8sUpdater

	// assert initial CiliumNode upsert has been sent to the events chan
	assert.Equal(t, "upsert", <-events)

	// Wait for agent pre-allocation request, then validate it
	assert.Equal(t, "upsert", <-events)
	currentNode = fakeK8sCiliumNodeAPI.currentNode()
	assert.ElementsMatch(t,
		[]types.IPAMPoolRequest{
			{Pool: "default", Needed: types.IPAMPoolDemand{IPv4Addrs: 16, IPv6Addrs: 16}},
			{Pool: "mars", Needed: types.IPAMPoolDemand{IPv4Addrs: 8, IPv6Addrs: 8}},
		},
		currentNode.Spec.IPAM.Pools.Requested,
	)
	assert.ElementsMatch(t,
		[]types.IPAMPoolAllocation{
			{
				Pool: "default",
				CIDRs: []types.IPAMPodCIDR{
					types.IPAMPodCIDR(defaultIPv4CIDR1.String()),
					types.IPAMPodCIDR(defaultIPv6CIDR1.String()),
				},
			},
			{
				Pool: "mars",
				CIDRs: []types.IPAMPodCIDR{
					types.IPAMPodCIDR(marsIPv4CIDR1.String()),
					types.IPAMPodCIDR(marsIPv6CIDR1.String()),
				},
			},
		},
		currentNode.Spec.IPAM.Pools.Allocated,
	)

	unusedIPv4CIDR1 := cidr.MustParseCIDR("10.0.33.0/24")
	unusedIPv6CIDR1 := cidr.MustParseCIDR("fd00:33::/96")

	// Assign further CIDRs to pools (i.e. this simulates the operator logic)
	allocatedPools := []types.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []types.IPAMPodCIDR{
				types.IPAMPodCIDR(defaultIPv4CIDR1.String()),
				types.IPAMPodCIDR(defaultIPv6CIDR1.String()),
			},
		},
		{
			Pool: "mars",
			CIDRs: []types.IPAMPodCIDR{
				types.IPAMPodCIDR(marsIPv4CIDR1.String()),
				types.IPAMPodCIDR(marsIPv6CIDR1.String()),
			},
		},
		{
			Pool: "unused",
			CIDRs: []types.IPAMPodCIDR{
				types.IPAMPodCIDR(unusedIPv4CIDR1.String()),
				types.IPAMPodCIDR(unusedIPv6CIDR1.String()),
			},
		},
	}
	currentNode.Spec.IPAM.Pools.Allocated = allocatedPools

	fakeK8sCiliumNodeAPI.updateNode(currentNode)
	assert.Equal(t, "upsert", <-events)
	c.waitForAllPools()

	// test allocation in default pool
	defaultAllocation, err := c.allocateIP(net.ParseIP("10.0.22.1"), "default-pod-1", "default", IPv4, false)
	assert.NoError(t, err)
	assert.Equal(t, defaultAllocation.IP, net.ParseIP("10.0.22.1"))

	// cannot allocate the same IP twice
	faultyAllocation, err := c.allocateIP(net.ParseIP("10.0.22.1"), "default-pod-1", "default", IPv4, false)
	assert.ErrorIs(t, err, ipallocator.ErrAllocated)
	assert.Nil(t, faultyAllocation)

	// Allocation from an unknown pool should create a new pending allocation
	jupiterIPv4CIDR := cidr.MustParseCIDR("192.168.1.0/16")
	juptierIPv6CIDR := cidr.MustParseCIDR("fc00:33::/96")

	faultyAllocation, err = c.allocateIP(net.ParseIP("192.168.1.1"), "jupiter-pod-0", "jupiter", IPv4, false)
	assert.ErrorIs(t, err, &ErrPoolNotReadyYet{})
	assert.Nil(t, faultyAllocation)
	faultyAllocation, err = c.allocateNext("jupiter-pod-1", "jupiter", IPv6, false)
	assert.ErrorIs(t, err, &ErrPoolNotReadyYet{})
	assert.Nil(t, faultyAllocation)
	// Try again. This should still fail, but not request an additional third IP
	// (since the owner has already attempted to allocate). This however sets
	// upstreamSync to 'true', which should populate .Spec.IPAM.Pools.Requested
	// with pending requests for the "jupiter" pool
	faultyAllocation, err = c.allocateNext("jupiter-pod-1", "jupiter", IPv6, true)
	assert.ErrorIs(t, err, &ErrPoolNotReadyYet{})
	assert.Nil(t, faultyAllocation)

	assert.Equal(t, "upsert", <-events)
	currentNode = fakeK8sCiliumNodeAPI.currentNode()
	// Check that the agent has not (yet) removed the unused pool.
	assert.Equal(t, allocatedPools, currentNode.Spec.IPAM.Pools.Allocated)
	// Check if the agent now requests one IPv4 and one IPv6 IP for the jupiter pool
	assert.Equal(t, []types.IPAMPoolRequest{
		{
			Pool: "default",
			Needed: types.IPAMPoolDemand{
				IPv4Addrs: 32, // 1 allocated + 16 pre-allocate, rounded up to multiple of 16
				IPv6Addrs: 16, // 0 allocated + 16 pre-allocate
			},
		},
		{
			Pool: "jupiter",
			Needed: types.IPAMPoolDemand{
				IPv4Addrs: 1, // 1 pending, no pre-allocate
				IPv6Addrs: 1, // 1 pending, no pre-allocate
			},
		},
		{
			Pool: "mars",
			Needed: types.IPAMPoolDemand{
				IPv4Addrs: 8, // 0 allocated + 8 pre-allocate
				IPv6Addrs: 8, // 0 allocated + 8 pre-allocate
			},
		},
	}, currentNode.Spec.IPAM.Pools.Requested)
	// Check that the local node store has been updated
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		localNode, err := fakeLocalNodeStore.Get(t.Context())
		assert.NoError(c, err)
		assert.Equalf(c,
			defaultIPv4CIDR1, localNode.IPv4AllocCIDR,
			"IPv4 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv4SecondaryAllocCIDRs, []*cidr.CIDR{marsIPv4CIDR1, unusedIPv4CIDR1},
			"IPv4 secondary allocation CIDRs do not match",
		)
		assert.Equalf(c,
			defaultIPv6CIDR1, localNode.IPv6AllocCIDR,
			"IPv6 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv6SecondaryAllocCIDRs, []*cidr.CIDR{marsIPv6CIDR1, unusedIPv6CIDR1},
			"IPv6 secondary allocation CIDRs do not match",
		)
	}, timeout, tick)

	c.restoreFinished(IPv4)
	c.restoreFinished(IPv6)

	// Assign the jupiter pool
	currentNode.Spec.IPAM.Pools.Allocated = []types.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []types.IPAMPodCIDR{
				types.IPAMPodCIDR(defaultIPv6CIDR1.String()),
				types.IPAMPodCIDR(defaultIPv4CIDR1.String()),
			},
		},
		{
			Pool: "jupiter",
			CIDRs: []types.IPAMPodCIDR{
				types.IPAMPodCIDR(jupiterIPv4CIDR.String()),
				types.IPAMPodCIDR(juptierIPv6CIDR.String()),
			},
		},
		{
			Pool: "mars",
			CIDRs: []types.IPAMPodCIDR{
				types.IPAMPodCIDR(marsIPv6CIDR1.String()),
				types.IPAMPodCIDR(marsIPv4CIDR1.String()),
			},
		},
		{
			Pool: "unused",
			CIDRs: []types.IPAMPodCIDR{
				types.IPAMPodCIDR(unusedIPv4CIDR1.String()),
				types.IPAMPodCIDR(unusedIPv6CIDR1.String()),
			},
		},
	}
	fakeK8sCiliumNodeAPI.updateNode(currentNode)
	assert.Equal(t, "upsert", <-events)

	c.waitForPool(t.Context(), IPv4, "jupiter")
	c.waitForPool(t.Context(), IPv6, "jupiter")

	// Allocations should now succeed
	jupiterIP0 := net.ParseIP("192.168.1.1")
	allocatedJupiterIP0, err := c.allocateIP(jupiterIP0, "jupiter-pod-0", "jupiter", IPv4, false)
	assert.NoError(t, err)
	assert.True(t, jupiterIP0.Equal(allocatedJupiterIP0.IP))
	allocatedJupiterIP1, err := c.allocateNext("jupiter-pod-1", "jupiter", IPv6, false)
	assert.NoError(t, err)
	assert.True(t, juptierIPv6CIDR.Contains(allocatedJupiterIP1.IP))

	// Release IPs from jupiter pool. This should fully remove it from both
	// "requested" and "allocated"
	err = c.releaseIP(allocatedJupiterIP0.IP, "jupiter", IPv4, false)
	assert.NoError(t, err)
	err = c.releaseIP(allocatedJupiterIP1.IP, "jupiter", IPv6, true) // triggers sync
	assert.NoError(t, err)

	// Wait for agent to release jupiter and unused CIDRs
	assert.Equal(t, "upsert", <-events)
	currentNode = fakeK8sCiliumNodeAPI.currentNode()
	assert.Equal(t, types.IPAMPoolSpec{
		Requested: []types.IPAMPoolRequest{
			{
				Pool: "default",
				Needed: types.IPAMPoolDemand{
					IPv4Addrs: 32, // 1 allocated + 16 pre-allocate, rounded up to multiple of 16
					IPv6Addrs: 16, // 0 allocated + 16 pre-allocate
				},
			},
			{
				Pool: "mars",
				Needed: types.IPAMPoolDemand{
					IPv4Addrs: 8, // 0 allocated + 8 pre-allocate
					IPv6Addrs: 8, // 0 allocated + 8 pre-allocate
				},
			},
		},
		Allocated: []types.IPAMPoolAllocation{
			{
				Pool: "default",
				CIDRs: []types.IPAMPodCIDR{
					types.IPAMPodCIDR(defaultIPv4CIDR1.String()),
					types.IPAMPodCIDR(defaultIPv6CIDR1.String()),
				},
			},
			{
				Pool: "mars",
				CIDRs: []types.IPAMPodCIDR{
					types.IPAMPodCIDR(marsIPv4CIDR1.String()),
					types.IPAMPodCIDR(marsIPv6CIDR1.String()),
				},
			},
		},
	}, currentNode.Spec.IPAM.Pools)
	// Wait for the agent to update the local node store after jupiter and unused release
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		localNode, err := fakeLocalNodeStore.Get(t.Context())
		assert.NoError(c, err)
		assert.Equalf(c,
			defaultIPv4CIDR1, localNode.IPv4AllocCIDR,
			"IPv4 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv4SecondaryAllocCIDRs, []*cidr.CIDR{marsIPv4CIDR1},
			"IPv4 secondary allocation CIDRs do not match",
		)
		assert.Equalf(c,
			defaultIPv6CIDR1, localNode.IPv6AllocCIDR,
			"IPv6 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv6SecondaryAllocCIDRs, []*cidr.CIDR{marsIPv6CIDR1},
			"IPv6 secondary allocation CIDRs do not match",
		)
	}, timeout, tick)

	// exhaust mars ipv4 pool (/27 contains 30 IPs)
	allocatedMarsIPs := []net.IP{}
	numMarsIPs := 30
	for i := range numMarsIPs {
		// set upstreamSync to true for last allocation, to ensure we only get one upsert event
		ar, err := c.allocateNext(fmt.Sprintf("mars-pod-%d", i), "mars", IPv4, i == numMarsIPs-1)
		assert.NoError(t, err)
		assert.True(t, marsIPv4CIDR1.Contains(ar.IP))
		allocatedMarsIPs = append(allocatedMarsIPs, ar.IP)
	}
	_, err = c.allocateNext("mars-pod-overflow", "mars", IPv4, false)
	assert.ErrorContains(t, err, "all pod CIDR ranges are exhausted")

	ipv4Dump, _ := c.dump(IPv4)
	assert.Len(t, ipv4Dump, 2) // 2 pools: default + mars
	assert.Len(t, ipv4Dump[PoolDefault()], 1)
	assert.Len(t, ipv4Dump[Pool("mars")], numMarsIPs)

	// Ensure Requested numbers are bumped
	assert.Equal(t, "upsert", <-events)
	currentNode = fakeK8sCiliumNodeAPI.currentNode()
	assert.Equal(t, []types.IPAMPoolRequest{
		{
			Pool: "default",
			Needed: types.IPAMPoolDemand{
				IPv4Addrs: 32, // 1 allocated + 16 pre-allocate, rounded up to multiple of 16
				IPv6Addrs: 16,
			},
		},
		{
			Pool: "mars",
			Needed: types.IPAMPoolDemand{
				IPv4Addrs: 40, // 30 allocated + 8 pre-allocate, rounded up to multiple of 8
				IPv6Addrs: 8,
			},
		},
	}, currentNode.Spec.IPAM.Pools.Requested)

	marsIPv4CIDR2 := cidr.MustParseCIDR("10.0.12.0/27")

	// Assign additional mars IPv4 CIDR
	currentNode.Spec.IPAM.Pools.Allocated = []types.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []types.IPAMPodCIDR{
				types.IPAMPodCIDR(defaultIPv4CIDR1.String()),
				types.IPAMPodCIDR(defaultIPv6CIDR1.String()),
			},
		},
		{
			Pool: "mars",
			CIDRs: []types.IPAMPodCIDR{
				types.IPAMPodCIDR(marsIPv4CIDR1.String()),
				types.IPAMPodCIDR(marsIPv4CIDR2.String()),
				types.IPAMPodCIDR(marsIPv6CIDR1.String()),
			},
		},
	}
	fakeK8sCiliumNodeAPI.updateNode(currentNode)
	assert.Equal(t, "upsert", <-events)

	// Should now be able to allocate from mars pool again
	marsAllocation, err := c.allocateNext("mars-pod-overflow", "mars", IPv4, false)
	assert.NoError(t, err)
	assert.True(t, marsIPv4CIDR2.Contains(marsAllocation.IP))

	// Deallocate all other IPs from mars pool. This should release the old CIDR
	for i, ip := range allocatedMarsIPs {
		err = c.releaseIP(ip, "mars", IPv4, i == numMarsIPs-1)
		assert.NoError(t, err)
	}
	assert.Equal(t, "upsert", <-events)
	currentNode = fakeK8sCiliumNodeAPI.currentNode()
	assert.Equal(t, []types.IPAMPoolRequest{
		{
			Pool: "default",
			Needed: types.IPAMPoolDemand{
				IPv4Addrs: 32, // 1 allocated + 16 pre-allocate, rounded up to multiple of 16
				IPv6Addrs: 16,
			},
		},
		{
			Pool: "mars",
			Needed: types.IPAMPoolDemand{
				IPv4Addrs: 16, // 1 allocated + 8 pre-allocate, rounded up to multiple of 8
				IPv6Addrs: 8,
			},
		},
	}, currentNode.Spec.IPAM.Pools.Requested)

	// Initial mars CIDR should have been marked as released now
	assert.Equal(t, []types.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []types.IPAMPodCIDR{
				types.IPAMPodCIDR(defaultIPv4CIDR1.String()),
				types.IPAMPodCIDR(defaultIPv6CIDR1.String()),
			},
		},
		{
			Pool: "mars",
			CIDRs: []types.IPAMPodCIDR{
				types.IPAMPodCIDR(marsIPv4CIDR2.String()),
				types.IPAMPodCIDR(marsIPv6CIDR1.String()),
			},
		},
	}, currentNode.Spec.IPAM.Pools.Allocated)

	// Wait for the agent to update the local node store after initial mars CIDR release
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		localNode, err := fakeLocalNodeStore.Get(t.Context())
		assert.NoError(c, err)
		assert.Equalf(c,
			defaultIPv4CIDR1, localNode.IPv4AllocCIDR,
			"IPv4 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv4SecondaryAllocCIDRs, []*cidr.CIDR{marsIPv4CIDR2},
			"IPv4 secondary allocation CIDRs do not match",
		)
		assert.Equalf(c,
			defaultIPv6CIDR1, localNode.IPv6AllocCIDR,
			"IPv6 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv6SecondaryAllocCIDRs, []*cidr.CIDR{marsIPv6CIDR1},
			"IPv6 secondary allocation CIDRs do not match",
		)
	}, timeout, tick)

	ipv4Dump, ipv4Summary := c.dump(IPv4)
	assert.Equal(t, map[Pool]map[string]string{
		PoolDefault(): {
			defaultAllocation.IP.String(): "",
		},
		Pool("mars"): {
			marsAllocation.IP.String(): "",
		},
	}, ipv4Dump)
	assert.Equal(t, "2 IPAM pool(s) available", ipv4Summary)
}

// Test_MultiPoolManager_ReleaseUnusedCIDR verifies that we release all unused CIDRs.
// Specifically /32's and /128's
func Test_MultiPoolManager_ReleaseUnusedCIDR(t *testing.T) {
	logger := hivetest.Logger(t)

	db := statedb.New()
	poolsTbl, err := podippool.NewTable(db)
	require.NoError(t, err)
	insertPool(t, db, poolsTbl, "default", false)

	fakeConfig := testConfiguration
	// disable pre-allocation
	fakeConfig.IPAMMultiPoolPreAllocation = map[string]string{}
	fakeOwner := &ownerMock{}
	fakeLocalNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	events := make(chan string, 2)
	cnEvents := make(chan resource.Event[*ciliumv2.CiliumNode])
	fakeK8sAPI := &fakeK8sCiliumNodeAPIResource{
		c:    cnEvents,
		node: &ciliumv2.CiliumNode{},
		onUpsertEvent: func(err error) {
			events <- "upsert"
		},
		onDeleteEvent: func(err error) {},
	}

	// Initial node owns two /32 IPv4 and two /128 IPv6 CIDRs
	cidr1 := cidr.MustParseCIDR("10.0.10.0/32")
	cidr2 := cidr.MustParseCIDR("10.0.11.0/32")
	cidrv61 := cidr.MustParseCIDR("fd00:10::/128")
	cidrv62 := cidr.MustParseCIDR("fd00:11::/128")
	initialNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeTypes.GetName()},
		Spec: ciliumv2.NodeSpec{
			IPAM: types.IPAMSpec{
				Pools: types.IPAMPoolSpec{
					Allocated: []types.IPAMPoolAllocation{{
						Pool: "default",
						CIDRs: []types.IPAMPodCIDR{
							types.IPAMPodCIDR(cidr1.String()),
							types.IPAMPodCIDR(cidr2.String()),
							types.IPAMPodCIDR(cidrv61.String()),
							types.IPAMPodCIDR(cidrv62.String()),
						},
					}},
				},
			},
		},
	}

	// Feed initial node to the fake API so that newMultiPoolManager returns immediately
	go fakeK8sAPI.updateNode(initialNode)

	mgr := newMultiPoolManager(MultiPoolManagerParams{
		Logger:         logger,
		Conf:           fakeConfig,
		Node:           fakeK8sAPI,
		Owner:          fakeOwner,
		LocalNodeStore: fakeLocalNodeStore,
		Clientset:      fakeK8sAPI,
		DB:             db,
		PodIPPools:     poolsTbl,
	})

	// Trigger controller immediately when requested by the IPAM trigger
	triggerNow, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: 0,
		TriggerFunc: func(_ []string) { mgr.controller.TriggerController(multiPoolControllerName) },
		Name:        "test-trigger",
	})
	assert.NoError(t, err)
	mgr.k8sUpdater = triggerNow

	<-events // first upsert (initial node)

	// Allocate one IPv4 and one IPv6 IP
	ipInCIDR1 := net.ParseIP("10.0.10.0")
	_, err = mgr.allocateIP(ipInCIDR1, "pod-a", "default", IPv4, false)
	assert.NoError(t, err)

	ipInCIDRv61 := net.ParseIP("fd00:10::")
	_, err = mgr.allocateIP(ipInCIDRv61, "pod-a", "default", IPv6, false)
	assert.NoError(t, err)

	// Mark restore finished so that releaseExcessCIDRsMultiPool() can run
	mgr.restoreFinished(IPv4)
	mgr.restoreFinished(IPv6)

	// Manually invoke updateLocalNode
	assert.NoError(t, mgr.updateLocalNode(context.TODO()))

	<-events // upsert generated by the update

	updated := fakeK8sAPI.currentNode()
	alloc := updated.Spec.IPAM.Pools.Allocated
	assert.Len(t, alloc, 1, "expected only one pool allocation entry")
	assert.Equal(t, "default", alloc[0].Pool)
	assert.ElementsMatch(t,
		[]types.IPAMPodCIDR{
			types.IPAMPodCIDR(cidr1.String()),
			types.IPAMPodCIDR(cidrv61.String()),
		},
		alloc[0].CIDRs,
		"unused CIDRs should have been released",
	)
}

// Test_MultiPoolManager_ReleaseUnusedCIDR_PreAllocBuffer verifies that when preAlloc > 0
// we keep enough /32 CIDRs to satisfy in-use IPs plus the buffer, and release the rest.
// Scenario:
//   - 10 /32 CIDRs allocated in pool "default"
//   - 5 of them are in use
//   - preAlloc = 1  => neededIPs = 5 (in-use) + 1 (buffer) = 6
func Test_MultiPoolManager_ReleaseUnusedCIDR_PreAlloc(t *testing.T) {
	logger := hivetest.Logger(t)

	db := statedb.New()
	poolsTbl, err := podippool.NewTable(db)
	require.NoError(t, err)
	insertPool(t, db, poolsTbl, "default", false)

	// preAlloc buffer of 1 for pool "default"
	fakeConfig := testConfiguration
	fakeConfig.IPAMMultiPoolPreAllocation = map[string]string{
		"default": "1",
	}

	fakeOwner := &ownerMock{}
	fakeLocalNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	events := make(chan string, 2)
	cnEvents := make(chan resource.Event[*ciliumv2.CiliumNode])
	fakeK8sAPI := &fakeK8sCiliumNodeAPIResource{
		c:    cnEvents,
		node: &ciliumv2.CiliumNode{},
		onUpsertEvent: func(err error) {
			events <- "upsert"
		},
		onDeleteEvent: func(err error) {},
	}

	// Create 10 distinct IPv4 /32 and IPv6 /128 CIDRs
	v4Cidrs := make([]*cidr.CIDR, 10)
	v6Cidrs := make([]*cidr.CIDR, 10)
	cidrPodCIDRs := make([]types.IPAMPodCIDR, 0, 20)
	for i := 0; i < 10; i++ {
		c4 := cidr.MustParseCIDR(fmt.Sprintf("10.0.100.%d/32", i))
		v4Cidrs[i] = c4
		cidrPodCIDRs = append(cidrPodCIDRs, types.IPAMPodCIDR(c4.String()))

		c6 := cidr.MustParseCIDR(fmt.Sprintf("fd00:100::%d/128", i))
		v6Cidrs[i] = c6
		cidrPodCIDRs = append(cidrPodCIDRs, types.IPAMPodCIDR(c6.String()))
	}

	initialNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeTypes.GetName()},
		Spec: ciliumv2.NodeSpec{
			IPAM: types.IPAMSpec{
				Pools: types.IPAMPoolSpec{
					Allocated: []types.IPAMPoolAllocation{{
						Pool:  "default",
						CIDRs: cidrPodCIDRs,
					}},
				},
			},
		},
	}

	// Feed initial node so that newMultiPoolManager returns immediately
	go fakeK8sAPI.updateNode(initialNode)

	mgr := newMultiPoolManager(MultiPoolManagerParams{
		Logger:         logger,
		Conf:           fakeConfig,
		Node:           fakeK8sAPI,
		Owner:          fakeOwner,
		LocalNodeStore: fakeLocalNodeStore,
		Clientset:      fakeK8sAPI,
		DB:             db,
		PodIPPools:     poolsTbl,
	})

	// Trigger controller immediately when requested
	triggerNow, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: 0,
		TriggerFunc: func(_ []string) { mgr.controller.TriggerController(multiPoolControllerName) },
		Name:        "test-trigger-prealloc",
	})
	assert.NoError(t, err)
	mgr.k8sUpdater = triggerNow

	<-events // first upsert (initial node)

	// Allocate 5 IPv4 and 5 IPv6 IPs
	for i := 0; i < 5; i++ {
		ip4 := net.ParseIP(fmt.Sprintf("10.0.100.%d", i))
		_, err := mgr.allocateIP(ip4, fmt.Sprintf("pod4-%d", i), "default", IPv4, false)
		assert.NoError(t, err)

		ip6 := net.ParseIP(fmt.Sprintf("fd00:100::%d", i))
		_, err = mgr.allocateIP(ip6, fmt.Sprintf("pod6-%d", i), "default", IPv6, false)
		assert.NoError(t, err)
	}

	// Mark restore finished so release code can run
	mgr.restoreFinished(IPv4)
	mgr.restoreFinished(IPv6)
	assert.NoError(t, mgr.updateLocalNode(context.TODO()))

	<-events // upsert generated by the update

	updated := fakeK8sAPI.currentNode()
	alloc := updated.Spec.IPAM.Pools.Allocated
	assert.Len(t, alloc, 1, "expected only one pool allocation entry")
	assert.Equal(t, "default", alloc[0].Pool)
	assert.Len(t, alloc[0].CIDRs, 12, "should retain 12 CIDRs (6 per family)")

	// Verify that all in-use CIDRs are still present
	remaining := map[string]struct{}{}
	for _, c := range alloc[0].CIDRs {
		remaining[string(c)] = struct{}{}
	}
	for i := 0; i < 5; i++ {
		assert.Contains(t, remaining, v4Cidrs[i].String(), "in-use CIDR %s should not be released", v4Cidrs[i].String())
		assert.Contains(t, remaining, v6Cidrs[i].String(), "in-use CIDR %s should not be released", v6Cidrs[i].String())
	}
}

func Test_neededIPCeil(t *testing.T) {
	tests := []struct {
		numIP    int
		preAlloc int
		want     int
	}{
		{0, 0, 0},
		{1, 0, 1},
		{3, 0, 3},
		{0, 1, 1},
		{1, 1, 2},
		{3, 1, 4},
		{0, 16, 16},
		{1, 16, 32},
		{15, 16, 32},
		{16, 16, 32},
		{17, 16, 48},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("numIP=%d_preAlloc=%d", tt.numIP, tt.preAlloc), func(t *testing.T) {
			assert.Equalf(t, tt.want, neededIPCeil(tt.numIP, tt.preAlloc), "neededIPCeil(%v, %v)", tt.numIP, tt.preAlloc)
		})
	}
}

func Test_pendingAllocationsPerPool(t *testing.T) {
	var now time.Time
	elapseTime := func(duration time.Duration) {
		now = now.Add(duration)
	}

	pending := pendingAllocationsPerPool{
		logger: hivetest.Logger(t),
		pools:  map[Pool]pendingAllocationsPerOwner{},
		clock: func() time.Time {
			return now
		},
	}

	pending.upsertPendingAllocation("test", "default/xwing", IPv4)
	pending.upsertPendingAllocation("other", "foo", IPv4)
	pending.upsertPendingAllocation("other", "foo", IPv6)
	pending.upsertPendingAllocation("other", "bar", IPv4)
	pending.upsertPendingAllocation("other", "bar", IPv6)
	pending.upsertPendingAllocation("other", "baz-ipv6-only", IPv6)

	elapseTime(30 * time.Second) // first time jump

	pending.upsertPendingAllocation("test", "default/tiefighter", IPv4) // new
	pending.upsertPendingAllocation("other", "foo", IPv4)               // renewal
	pending.upsertPendingAllocation("other", "foo", IPv6)               // renewal

	// Nothing should expire
	pending.removeExpiredEntries()
	assert.Equal(t, 2, pending.pendingForPool("test", IPv4))
	assert.Equal(t, 0, pending.pendingForPool("test", IPv6))
	assert.Equal(t, 2, pending.pendingForPool("other", IPv4))
	assert.Equal(t, 3, pending.pendingForPool("other", IPv6))

	elapseTime(pendingAllocationTTL) // second time jump

	// This should clean up everything before the first time jump
	pending.removeExpiredEntries()
	assert.Equal(t, 1, pending.pendingForPool("test", IPv4))
	assert.Equal(t, 0, pending.pendingForPool("test", IPv6))
	assert.Equal(t, 1, pending.pendingForPool("other", IPv4))
	assert.Equal(t, 1, pending.pendingForPool("other", IPv6))

	// Mark entries on "other" pool as allocated
	pending.markAsAllocated("other", "foo", IPv4)
	assert.Equal(t, 0, pending.pendingForPool("other", IPv4))
	assert.Equal(t, 1, pending.pendingForPool("other", IPv6))
	pending.markAsAllocated("other", "foo", IPv6)
	assert.Equal(t, 0, pending.pendingForPool("other", IPv4))
	assert.Equal(t, 0, pending.pendingForPool("other", IPv6))
}

type fakeK8sCiliumNodeAPIResource struct {
	mutex lock.Mutex
	node  *ciliumv2.CiliumNode
	c     chan resource.Event[*ciliumv2.CiliumNode]

	onUpsertEvent func(err error)
	onDeleteEvent func(err error)
}

func (f *fakeK8sCiliumNodeAPIResource) Update(ctx context.Context, ciliumNode *ciliumv2.CiliumNode, _ metav1.UpdateOptions) (*ciliumv2.CiliumNode, error) {
	err := f.updateNode(ciliumNode)
	return ciliumNode, err
}

func (f *fakeK8sCiliumNodeAPIResource) UpdateStatus(ctx context.Context, ciliumNode *ciliumv2.CiliumNode, _ metav1.UpdateOptions) (*ciliumv2.CiliumNode, error) {
	err := f.updateNode(ciliumNode)
	return ciliumNode, err
}

func (f *fakeK8sCiliumNodeAPIResource) Observe(ctx context.Context, next func(resource.Event[*ciliumv2.CiliumNode]), complete func(error)) {
	panic("unimplemented")
}

func (f *fakeK8sCiliumNodeAPIResource) Events(ctx context.Context, _ ...resource.EventsOpt) <-chan resource.Event[*ciliumv2.CiliumNode] {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	return f.c
}

func (f *fakeK8sCiliumNodeAPIResource) Store(context.Context) (resource.Store[*ciliumv2.CiliumNode], error) {
	return nil, errors.New("unimplemented")
}

// currentNode returns a the current snapshot of the node
func (f *fakeK8sCiliumNodeAPIResource) currentNode() *ciliumv2.CiliumNode {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	return f.node.DeepCopy()
}

// updateNode is to be invoked by the test code to simulate updates by the operator
func (f *fakeK8sCiliumNodeAPIResource) updateNode(newNode *ciliumv2.CiliumNode) error {
	f.mutex.Lock()
	oldNode := f.node
	if oldNode == nil {
		f.mutex.Unlock()
		return fmt.Errorf("failed to update CiliumNode %q: node not found", newNode.Name)
	}
	f.node = newNode.DeepCopy()

	c := f.c
	onUpsertEvent := f.onUpsertEvent
	f.mutex.Unlock()

	c <- resource.Event[*ciliumv2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: newNode,
		Key:    resource.NewKey(newNode),
		Done: func(err error) {
			if onUpsertEvent != nil {
				onUpsertEvent(err)
			}
		}}

	return nil
}

func TestAllocateNextFamily_SkipMasquerade(t *testing.T) {
	db := statedb.New()
	poolsTbl, err := podippool.NewTable(db)
	require.NoError(t, err)

	insertPool(t, db, poolsTbl, "default", false)
	insertPool(t, db, poolsTbl, "blue", false)
	insertPool(t, db, poolsTbl, "red", true) // skip-masquerade annotation
	insertPool(t, db, poolsTbl, "green", false)

	// onlyMasqueradeDefaultPool = true, non-default pool
	mgr := createSkipMasqTestManager(t, db, poolsTbl, true)
	res, err := mgr.allocateNext("ns/pod", "blue", IPv4, false)
	require.NoError(t, err)
	require.True(t, res.SkipMasquerade, "SkipMasquerade should be true for non-default pools when onlyMasqueradeDefaultPool is set")

	// onlyMasqueradeDefaultPool = true, default pool
	res, err = mgr.allocateNext("ns/pod", "default", IPv4, false)
	require.NoError(t, err)
	require.False(t, res.SkipMasquerade, "default pool should always be masqueraded even if global flag set")

	// onlyMasqueradeDefaultPool = false but pool annotated with skip-masquerade
	mgr = createSkipMasqTestManager(t, db, poolsTbl, false)
	res, err = mgr.allocateNext("ns/pod", "red", IPv4, false)
	require.NoError(t, err)
	require.True(t, res.SkipMasquerade, "SkipMasquerade should be true based on pool annotation")

	// honour annotation on default pool also
	insertPool(t, db, poolsTbl, "default", true)
	mgr = createSkipMasqTestManager(t, db, poolsTbl, false)
	res, err = mgr.allocateNext("ns/pod", "default", IPv4, false)
	require.NoError(t, err)
	require.True(t, res.SkipMasquerade, "default pool should not be masqueraded if annotation set")

	// neither flag nor annotation set
	mgr = createSkipMasqTestManager(t, db, poolsTbl, false)
	res, err = mgr.allocateNext("ns/pod", "green", IPv4, false)
	require.NoError(t, err)
	require.False(t, res.SkipMasquerade, "SkipMasquerade should default to false")
}

func insertPool(t *testing.T, db *statedb.DB, tbl statedb.RWTable[podippool.LocalPodIPPool], name string, skipMasq bool) {
	t.Helper()
	ann := map[string]string{}
	if skipMasq {
		ann[annotation.IPAMSkipMasquerade] = "true"
	}

	poolObj := podippool.LocalPodIPPool{
		CiliumPodIPPool: &k8sv2alpha1.CiliumPodIPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Annotations: ann,
			},
		},
		UpdatedAt: time.Now(),
	}

	w := db.WriteTxn(tbl)
	tbl.Insert(w, poolObj)
	w.Commit()
}

func createSkipMasqTestManager(t *testing.T, db *statedb.DB, pools statedb.Table[podippool.LocalPodIPPool], onlyMasqDefault bool) *multiPoolManager {
	t.Helper()

	fakeConfig := testConfiguration
	fakeConfig.IPAMMultiPoolPreAllocation = map[string]string{}
	fakeOwner := &ownerMock{}
	fakeLocalNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	cnEvents := make(chan resource.Event[*ciliumv2.CiliumNode])
	fakeK8sAPI := &fakeK8sCiliumNodeAPIResource{
		c:             cnEvents,
		node:          &ciliumv2.CiliumNode{},
		onUpsertEvent: func(err error) {},
		onDeleteEvent: func(err error) {},
	}

	initialNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeTypes.GetName()},
		Spec: ciliumv2.NodeSpec{
			IPAM: types.IPAMSpec{
				Pools: types.IPAMPoolSpec{
					Allocated: []types.IPAMPoolAllocation{
						{Pool: "default", CIDRs: []types.IPAMPodCIDR{"10.0.0.0/24"}},
						{Pool: "blue", CIDRs: []types.IPAMPodCIDR{"10.0.1.0/24"}},
						{Pool: "red", CIDRs: []types.IPAMPodCIDR{"10.0.2.0/24"}},
						{Pool: "green", CIDRs: []types.IPAMPodCIDR{"10.0.3.0/24"}},
					},
				},
			},
		},
	}

	go fakeK8sAPI.updateNode(initialNode)

	mgr := newMultiPoolManager(MultiPoolManagerParams{
		Logger:                    hivetest.Logger(t),
		Conf:                      fakeConfig,
		Node:                      fakeK8sAPI,
		Owner:                     fakeOwner,
		LocalNodeStore:            fakeLocalNodeStore,
		Clientset:                 fakeK8sAPI,
		DB:                        db,
		PodIPPools:                pools,
		OnlyMasqueradeDefaultPool: onlyMasqDefault,
	})

	return mgr
}
