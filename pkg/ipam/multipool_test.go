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

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/trigger"
)

func Test_MultiPoolManager(t *testing.T) {
	fakeConfig := &testConfiguration{}
	fakeOwner := &ownerMock{}
	events := make(chan string, 1)
	fakeK8sCiliumNodeAPI := &fakeK8sCiliumNodeAPI{
		node: &ciliumv2.CiliumNode{},
		onDeleteEvent: func() {
			events <- "delete"
		},
		onUpsertEvent: func() {
			events <- "upsert"
		},
	}
	c := newMultiPoolManager(fakeConfig, fakeK8sCiliumNodeAPI, fakeOwner, fakeK8sCiliumNodeAPI)
	// set custom preAllocMap to not rely on option.Config in unit tests
	c.preallocatedIPsPerPool = preAllocatePerPool{
		"default": 16,
		"mars":    8,
	}
	// For testing, we want every trigger to run the controller once
	k8sUpdater, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: 0,
		TriggerFunc: func(reasons []string) {
			c.controller.TriggerController(multiPoolControllerName)
		},
		Name: multiPoolTriggerName,
	})
	assert.Nil(t, err)
	c.k8sUpdater = k8sUpdater

	currentNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeTypes.GetName()},
	}
	// provide initial CiliumNode CRD - we expect the agent to request the preAlloc pools
	fakeK8sCiliumNodeAPI.updateNode(currentNode)
	assert.Equal(t, <-events, "upsert")

	// Wait for agent pre-allocation request, then validate it
	assert.Equal(t, <-events, "upsert")
	currentNode = fakeK8sCiliumNodeAPI.currentNode()
	assert.Equal(t, &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeTypes.GetName()},
		Spec: ciliumv2.NodeSpec{IPAM: types.IPAMSpec{
			Pools: types.IPAMPoolSpec{
				Requested: []types.IPAMPoolRequest{
					{Pool: "default", Needed: types.IPAMPoolDemand{IPv4Addrs: 16, IPv6Addrs: 16}},
					{Pool: "mars", Needed: types.IPAMPoolDemand{IPv4Addrs: 8, IPv6Addrs: 8}},
				},
				Allocated: []types.IPAMPoolAllocation{},
			},
		}},
	}, currentNode)

	marsIPv4CIDR1 := cidr.MustParseCIDR("10.0.11.0/27")
	marsIPv6CIDR1 := cidr.MustParseCIDR("fd00:11::/123")
	defaultIPv4CIDR1 := cidr.MustParseCIDR("10.0.22.0/24")
	defaultIPv6CIDR1 := cidr.MustParseCIDR("fd00:22::/96")

	// Assign CIDR to pools (i.e. this simulates the operator logic)
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
				types.IPAMPodCIDR(marsIPv6CIDR1.String()),
			},
		},
	}

	fakeK8sCiliumNodeAPI.updateNode(currentNode)
	assert.Equal(t, <-events, "upsert")
	c.waitForAllPools()

	// test allocation in default pool
	defaultAllocation, err := c.allocateIP(net.ParseIP("10.0.22.1"), "default-pod-1", "default", IPv4, false)
	assert.Nil(t, err)
	assert.Equal(t, defaultAllocation.IP, net.ParseIP("10.0.22.1"))

	// cannot allocate the same IP twice
	faultyAllocation, err := c.allocateIP(net.ParseIP("10.0.22.1"), "default-pod-1", "default", IPv4, false)
	assert.Error(t, err, ipallocator.ErrAllocated)
	assert.Nil(t, faultyAllocation)

	// Allocation from an unknown pool should create a new pending allocation
	jupiterIPv4CIDR := cidr.MustParseCIDR("192.168.1.0/16")
	juptierIPv6CIDR := cidr.MustParseCIDR("fc00:33::/96")

	faultyAllocation, err = c.allocateIP(net.ParseIP("192.168.1.1"), "jupiter-pod-0", "jupiter", IPv4, false)
	assert.ErrorContains(t, err, "pool not (yet) available")
	assert.Nil(t, faultyAllocation)
	faultyAllocation, err = c.allocateNext("jupiter-pod-1", "jupiter", IPv6, false)
	assert.ErrorContains(t, err, "pool not (yet) available")
	assert.Nil(t, faultyAllocation)
	// Try again. This should still fail, but not request an additional third IP
	// (since the owner has already attempted to allocate). This however sets
	// upstreamSync to 'true', which should populate .Spec.IPAM.Pools.Requested
	// with pending requests for the "jupiter" pool
	faultyAllocation, err = c.allocateNext("jupiter-pod-1", "jupiter", IPv6, true)
	assert.ErrorContains(t, err, "pool not (yet) available")
	assert.Nil(t, faultyAllocation)

	// Check if the agent now requests one IPv4 and one IPv6 IP for the jupiter pool
	assert.Equal(t, <-events, "upsert")
	currentNode = fakeK8sCiliumNodeAPI.currentNode()
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
	}
	fakeK8sCiliumNodeAPI.updateNode(currentNode)
	assert.Equal(t, <-events, "upsert")

	c.waitForPool(context.TODO(), IPv4, "jupiter")
	c.waitForPool(context.TODO(), IPv6, "jupiter")

	// Allocations should now succeed
	jupiterIP0 := net.ParseIP("192.168.1.1")
	allocatedJupiterIP0, err := c.allocateIP(jupiterIP0, "jupiter-pod-0", "jupiter", IPv4, false)
	assert.Nil(t, err)
	assert.True(t, jupiterIP0.Equal(allocatedJupiterIP0.IP))
	allocatedJupiterIP1, err := c.allocateNext("jupiter-pod-1", "jupiter", IPv6, false)
	assert.Nil(t, err)
	assert.True(t, juptierIPv6CIDR.Contains(allocatedJupiterIP1.IP))

	// Release IPs from jupiter pool. This should fully remove it from both
	// "requested" and "allocated"
	err = c.releaseIP(allocatedJupiterIP0.IP, "jupiter", IPv4, false)
	assert.Nil(t, err)
	err = c.releaseIP(allocatedJupiterIP1.IP, "jupiter", IPv6, true) // triggers sync
	assert.Nil(t, err)

	// Wait for agent to release jupiter CIDRs
	assert.Equal(t, <-events, "upsert")
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

	// exhaust mars ipv4 pool (/27 contains 30 IPs)
	allocatedMarsIPs := []net.IP{}
	numMarsIPs := 30
	for i := 0; i < numMarsIPs; i++ {
		// set upstreamSync to true for last allocation, to ensure we only get one upsert event
		ar, err := c.allocateNext(fmt.Sprintf("mars-pod-%d", i), "mars", IPv4, i == numMarsIPs-1)
		assert.Nil(t, err)
		assert.True(t, marsIPv4CIDR1.Contains(ar.IP))
		allocatedMarsIPs = append(allocatedMarsIPs, ar.IP)
	}
	_, err = c.allocateNext("mars-pod-overflow", "mars", IPv4, false)
	assert.Error(t, errors.New("all pod CIDR ranges are exhausted"), err)

	ipv4Dump, _ := c.dump(IPv4)
	assert.Len(t, ipv4Dump, numMarsIPs+1) // +1 from default pool

	// Ensure Requested numbers are bumped
	assert.Equal(t, <-events, "upsert")
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
	assert.Equal(t, <-events, "upsert")

	// Should now be able to allocate from mars pool again
	marsAllocation, err := c.allocateNext("mars-pod-overflow", "mars", IPv4, false)
	assert.Nil(t, err)
	assert.True(t, marsIPv4CIDR2.Contains(marsAllocation.IP))

	// Deallocate all other IPs from mars pool. This should release the old CIDR
	for i, ip := range allocatedMarsIPs {
		err = c.releaseIP(ip, "mars", IPv4, i == numMarsIPs-1)
		assert.Nil(t, err)
	}
	assert.Equal(t, <-events, "upsert")
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

	ipv4Dump, ipv4Summary := c.dump(IPv4)
	assert.Equal(t, map[string]string{
		defaultAllocation.IP.String():        "",
		"mars/" + marsAllocation.IP.String(): "",
	}, ipv4Dump)
	assert.Equal(t, "2 IPAM pool(s) available", ipv4Summary)
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
		pools: map[Pool]pendingAllocationsPerOwner{},
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
