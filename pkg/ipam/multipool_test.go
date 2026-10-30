// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	apiMock "github.com/cilium/cilium/pkg/aws/api/mock"
	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipam/podippool"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func Test_MultiPoolManager(t *testing.T) {
	var (
		tick    = 10 * time.Millisecond
		timeout = 2 * refreshPoolInterval
	)

	nodeTypes.SetName("test-node")

	defaultIPv4CIDR1 := netip.MustParsePrefix("10.0.22.0/24")
	defaultIPv6CIDR1 := netip.MustParsePrefix("fd00:22::/96")
	marsIPv4CIDR1 := netip.MustParsePrefix("10.0.11.0/27")
	marsIPv6CIDR1 := netip.MustParsePrefix("fd00:11::/123")

	currentNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeTypes.GetName()},
		Spec: ciliumv2.NodeSpec{
			IPAM: types.IPAMSpec{
				Pools: types.IPAMPoolSpec{
					Allocated: []types.IPAMPoolAllocation{
						{
							Pool: "default",
							CIDRs: []iputil.Prefix{
								iputil.PrefixFrom(defaultIPv4CIDR1),
								iputil.PrefixFrom(defaultIPv6CIDR1),
							},
						},
						{
							Pool:        "mars",
							AllowLastIP: true,
							CIDRs: []iputil.Prefix{
								iputil.PrefixFrom(marsIPv4CIDR1),
								iputil.PrefixFrom(marsIPv6CIDR1),
							},
						},
					},
				},
			},
		},
	}

	synctest.Test(t, func(t *testing.T) {
		var (
			jg        job.Group
			localNode k8s.LocalCiliumNodeResource
			clientset *k8sClient.FakeClientset
		)
		h := hive.New(
			k8s.ResourcesCell,
			k8sClient.FakeClientCell(),
			cell.Provide(func() *node.LocalNodeStore { return node.NewTestLocalNodeStore(node.LocalNode{}) }),
			cell.Invoke(
				func(
					jg_ job.Group,
					localNode_ k8s.LocalCiliumNodeResource,
					localNodeStore_ *node.LocalNodeStore,
					clientset_ *k8sClient.FakeClientset,
				) {
					jg = jg_
					localNode = localNode_
					clientset = clientset_
				},
			),
		)

		tlog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
		assert.NoError(t, h.Start(tlog, t.Context()))
		t.Cleanup(func() { h.Stop(tlog, context.Background()) })

		// create local node
		_, err := clientset.CiliumV2().CiliumNodes().Create(t.Context(), currentNode, metav1.CreateOptions{})
		assert.NoError(t, err)

		preallocMap, err := ParseMultiPoolPreAllocMap(map[string]string{
			"default": "16",
			"mars":    "8",
		})
		assert.NoError(t, err)

		mgr := NewMultiPoolManager(MultiPoolManagerParams{
			Logger:               hivetest.Logger(t),
			IPv4Enabled:          true,
			IPv6Enabled:          true,
			CiliumNodeUpdateRate: time.Nanosecond,
			PreallocMap:          preallocMap,
			Node:                 localNode,
			CNClient:             clientset.CiliumV2().CiliumNodes(),
			JobGroup:             jg,
			PoolSpecAccessors:    MultiPoolAccessor,
		})

		// Wait for agent pre-allocation request, then validate it
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			currentNode, err := clientset.CiliumV2().CiliumNodes().Get(t.Context(), nodeTypes.GetName(), metav1.GetOptions{})
			assert.NoError(c, err)

			assert.ElementsMatch(c,
				[]types.IPAMPoolRequest{
					{Pool: "default", Needed: types.IPAMPoolDemand{IPv4Addrs: 16, IPv6Addrs: 16}},
					{Pool: "mars", Needed: types.IPAMPoolDemand{IPv4Addrs: 8, IPv6Addrs: 8}},
				},
				currentNode.Spec.IPAM.Pools.Requested,
			)
			assert.ElementsMatch(c,
				[]types.IPAMPoolAllocation{
					{
						Pool: "default",
						CIDRs: []iputil.Prefix{
							iputil.PrefixFrom(defaultIPv4CIDR1),
							iputil.PrefixFrom(defaultIPv6CIDR1),
						},
					},
					{
						Pool:        "mars",
						AllowLastIP: true,
						CIDRs: []iputil.Prefix{
							iputil.PrefixFrom(marsIPv4CIDR1),
							iputil.PrefixFrom(marsIPv6CIDR1),
						},
					},
				},
				currentNode.Spec.IPAM.Pools.Allocated,
			)
		}, timeout, tick)

		unusedIPv4CIDR1 := netip.MustParsePrefix("10.0.33.0/24")
		unusedIPv6CIDR1 := netip.MustParsePrefix("fd00:33::/96")

		// Assign further CIDRs to pools (i.e. this simulates the operator logic)
		currentNode, err = clientset.CiliumV2().CiliumNodes().Get(t.Context(), nodeTypes.GetName(), metav1.GetOptions{})
		assert.NoError(t, err)

		updNode := currentNode.DeepCopy()
		allocatedPools := []types.IPAMPoolAllocation{
			{
				Pool: "default",
				CIDRs: []iputil.Prefix{
					iputil.PrefixFrom(defaultIPv4CIDR1),
					iputil.PrefixFrom(defaultIPv6CIDR1),
				},
			},
			{
				Pool:        "mars",
				AllowLastIP: true,
				CIDRs: []iputil.Prefix{
					iputil.PrefixFrom(marsIPv4CIDR1),
					iputil.PrefixFrom(marsIPv6CIDR1),
				},
			},
			{
				Pool: "unused",
				CIDRs: []iputil.Prefix{
					iputil.PrefixFrom(unusedIPv4CIDR1),
					iputil.PrefixFrom(unusedIPv6CIDR1),
				},
			},
		}
		updNode.Spec.IPAM.Pools.Allocated = allocatedPools

		_, err = clientset.CiliumV2().CiliumNodes().Update(t.Context(), updNode, metav1.UpdateOptions{})
		assert.NoError(t, err)

		mgr.waitForAllPools()

		// test allocation in default pool
		defaultAllocation, err := mgr.AllocateIP(netip.MustParseAddr("10.0.22.1"), "default-pod-1", "default", IPv4, false)
		assert.NoError(t, err)
		assert.Equal(t, netip.MustParseAddr("10.0.22.1"), defaultAllocation.IP)

		// cannot allocate the same IP twice
		faultyAllocation, err := mgr.AllocateIP(netip.MustParseAddr("10.0.22.1"), "default-pod-1", "default", IPv4, false)
		assert.ErrorIs(t, err, ipallocator.ErrAllocated)
		assert.Nil(t, faultyAllocation)

		// Allocation from an unknown pool should create a new pending allocation
		jupiterIPv4CIDR := netip.MustParsePrefix("192.168.1.0/16")
		juptierIPv6CIDR := netip.MustParsePrefix("fc00:33::/96")

		faultyAllocation, err = mgr.AllocateIP(netip.MustParseAddr("192.168.1.1"), "jupiter-pod-0", "jupiter", IPv4, false)
		assert.ErrorIs(t, err, &ErrPoolNotReadyYet{})
		assert.Nil(t, faultyAllocation)
		faultyAllocation, err = mgr.AllocateNext("jupiter-pod-1", "jupiter", IPv6, false)
		assert.ErrorIs(t, err, &ErrPoolNotReadyYet{})
		assert.Nil(t, faultyAllocation)

		// Try again. This should still fail, but not request an additional third IP
		// (since the owner has already attempted to allocate). This however sets
		// upstreamSync to 'true', which should populate .Spec.IPAM.Pools.Requested
		// with pending requests for the "jupiter" pool
		faultyAllocation, err = mgr.AllocateNext("jupiter-pod-1", "jupiter", IPv6, true)
		assert.ErrorIs(t, err, &ErrPoolNotReadyYet{})
		assert.Nil(t, faultyAllocation)

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			currentNode, err = clientset.CiliumV2().CiliumNodes().Get(t.Context(), nodeTypes.GetName(), metav1.GetOptions{})
			assert.NoError(c, err)

			// Check that the agent has not (yet) removed the unused pool.
			assert.Equal(c, allocatedPools, currentNode.Spec.IPAM.Pools.Allocated)
			// Check if the agent now requests one IPv4 and one IPv6 IP for the jupiter pool
			assert.Equal(c, []types.IPAMPoolRequest{
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
		}, timeout, tick)

		mgr.RestoreFinished(IPv4)
		mgr.RestoreFinished(IPv6)

		// Assign the jupiter pool
		currentNode, err = clientset.CiliumV2().CiliumNodes().Get(t.Context(), nodeTypes.GetName(), metav1.GetOptions{})
		assert.NoError(t, err)

		updNode = currentNode.DeepCopy()
		updNode.Spec.IPAM.Pools.Allocated = []types.IPAMPoolAllocation{
			{
				Pool: "default",
				CIDRs: []iputil.Prefix{
					iputil.PrefixFrom(defaultIPv6CIDR1),
					iputil.PrefixFrom(defaultIPv4CIDR1),
				},
			},
			{
				Pool: "jupiter",
				CIDRs: []iputil.Prefix{
					iputil.PrefixFrom(jupiterIPv4CIDR),
					iputil.PrefixFrom(juptierIPv6CIDR),
				},
			},
			{
				Pool:        "mars",
				AllowLastIP: true,
				CIDRs: []iputil.Prefix{
					iputil.PrefixFrom(marsIPv6CIDR1),
					iputil.PrefixFrom(marsIPv4CIDR1),
				},
			},
			{
				Pool: "unused",
				CIDRs: []iputil.Prefix{
					iputil.PrefixFrom(unusedIPv4CIDR1),
					iputil.PrefixFrom(unusedIPv6CIDR1),
				},
			},
		}
		_, err = clientset.CiliumV2().CiliumNodes().Update(t.Context(), updNode, metav1.UpdateOptions{})
		assert.NoError(t, err)

		assert.True(t, mgr.waitForPool(t.Context(), IPv4, "jupiter"))
		assert.True(t, mgr.waitForPool(t.Context(), IPv6, "jupiter"))

		// Allocations should now succeed
		jupiterIP0 := netip.MustParseAddr("192.168.1.1")
		allocatedJupiterIP0, err := mgr.AllocateIP(jupiterIP0, "jupiter-pod-0", "jupiter", IPv4, false)
		require.NoError(t, err)
		require.NotNil(t, allocatedJupiterIP0)
		assert.Equal(t, jupiterIP0, allocatedJupiterIP0.IP)

		allocatedJupiterIP1, err := mgr.AllocateNext("jupiter-pod-1", "jupiter", IPv6, false)
		require.NoError(t, err)
		require.NotNil(t, allocatedJupiterIP1)
		assert.True(t, juptierIPv6CIDR.Contains(allocatedJupiterIP1.IP))

		// Release IPs from jupiter pool. This should fully remove it from both
		// "requested" and "allocated"
		err = mgr.ReleaseIP(allocatedJupiterIP0.IP, "jupiter", IPv4, false)
		assert.NoError(t, err)
		err = mgr.ReleaseIP(allocatedJupiterIP1.IP, "jupiter", IPv6, true) // triggers sync
		assert.NoError(t, err)

		// Wait for agent to release jupiter and unused CIDRs
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			currentNode, err = clientset.CiliumV2().CiliumNodes().Get(t.Context(), nodeTypes.GetName(), metav1.GetOptions{})
			assert.NoError(c, err)
			assert.Equal(c, types.IPAMPoolSpec{
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
						CIDRs: []iputil.Prefix{
							iputil.PrefixFrom(defaultIPv4CIDR1),
							iputil.PrefixFrom(defaultIPv6CIDR1),
						},
					},
					{
						Pool:        "mars",
						AllowLastIP: true,
						CIDRs: []iputil.Prefix{
							iputil.PrefixFrom(marsIPv4CIDR1),
							iputil.PrefixFrom(marsIPv6CIDR1),
						},
					},
				},
			}, currentNode.Spec.IPAM.Pools)
		}, timeout, tick)

		// exhaust mars ipv4 pool (/27 contains 31 IPs with allowLastIP enabled)
		allocatedMarsIPs := []netip.Addr{}
		numMarsIPs := 31
		for i := range numMarsIPs {
			// set upstreamSync to true for last allocation, to ensure we only get one upsert event
			ar, err := mgr.AllocateNext(fmt.Sprintf("mars-pod-%d", i), "mars", IPv4, i == numMarsIPs-1)
			assert.NoError(t, err)
			require.NotNil(t, ar)
			assert.True(t, marsIPv4CIDR1.Contains(ar.IP))
			allocatedMarsIPs = append(allocatedMarsIPs, ar.IP)
		}
		_, err = mgr.AllocateNext("mars-pod-overflow", "mars", IPv4, false)
		assert.ErrorContains(t, err, "all CIDR ranges are exhausted")

		ipv4Dump, _ := mgr.dump(IPv4)
		assert.Len(t, ipv4Dump, 2) // 2 pools: default + mars
		assert.Len(t, ipv4Dump[PoolDefault()], 1)
		assert.Len(t, ipv4Dump[Pool("mars")], numMarsIPs)

		// Ensure Requested numbers are bumped
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			currentNode, err = clientset.CiliumV2().CiliumNodes().Get(t.Context(), nodeTypes.GetName(), metav1.GetOptions{})
			assert.NoError(c, err)
			assert.Equal(c, []types.IPAMPoolRequest{
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
						IPv4Addrs: 40, // 31 allocated + 8 pre-allocate, rounded up to multiple of 8
						IPv6Addrs: 8,
					},
				},
			}, currentNode.Spec.IPAM.Pools.Requested)
		}, timeout, tick)

		marsIPv4CIDR2 := netip.MustParsePrefix("10.0.12.0/27")

		// Assign additional mars IPv4 CIDR
		currentNode, err = clientset.CiliumV2().CiliumNodes().Get(t.Context(), nodeTypes.GetName(), metav1.GetOptions{})
		assert.NoError(t, err)

		updNode = currentNode.DeepCopy()
		updNode.Spec.IPAM.Pools.Allocated = []types.IPAMPoolAllocation{
			{
				Pool: "default",
				CIDRs: []iputil.Prefix{
					iputil.PrefixFrom(defaultIPv4CIDR1),
					iputil.PrefixFrom(defaultIPv6CIDR1),
				},
			},
			{
				Pool:        "mars",
				AllowLastIP: true,
				CIDRs: []iputil.Prefix{
					iputil.PrefixFrom(marsIPv4CIDR1),
					iputil.PrefixFrom(marsIPv4CIDR2),
					iputil.PrefixFrom(marsIPv6CIDR1),
				},
			},
		}
		_, err = clientset.CiliumV2().CiliumNodes().Update(t.Context(), updNode, metav1.UpdateOptions{})
		assert.NoError(t, err)

		var marsAllocation *AllocationResult

		// Should eventually be able to allocate from mars pool again
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			marsAllocation, err = mgr.AllocateNext("mars-pod-overflow", "mars", IPv4, false)
			require.NoError(c, err)
			require.NotNil(c, marsAllocation)
			assert.True(c, marsIPv4CIDR2.Contains(marsAllocation.IP))
		}, timeout, tick)

		// Deallocate all other IPs from mars pool. This should release the old CIDR
		for i, addr := range allocatedMarsIPs {
			err = mgr.ReleaseIP(addr, "mars", IPv4, i == numMarsIPs-1)
			assert.NoError(t, err)
		}

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			currentNode, err = clientset.CiliumV2().CiliumNodes().Get(t.Context(), nodeTypes.GetName(), metav1.GetOptions{})
			assert.NoError(c, err)

			assert.Equal(c, []types.IPAMPoolRequest{
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
			assert.Equal(c, []types.IPAMPoolAllocation{
				{
					Pool: "default",
					CIDRs: []iputil.Prefix{
						iputil.PrefixFrom(defaultIPv4CIDR1),
						iputil.PrefixFrom(defaultIPv6CIDR1),
					},
				},
				{
					Pool:        "mars",
					AllowLastIP: true,
					CIDRs: []iputil.Prefix{
						iputil.PrefixFrom(marsIPv4CIDR2),
						iputil.PrefixFrom(marsIPv6CIDR1),
					},
				},
			}, currentNode.Spec.IPAM.Pools.Allocated)
		}, timeout, tick)

		ipv4Dump, ipv4Summary := mgr.dump(IPv4)
		assert.Equal(t, map[Pool]sets.Set[netip.Addr]{
			PoolDefault(): sets.New(defaultAllocation.IP),
			Pool("mars"):  sets.New(marsAllocation.IP),
		}, ipv4Dump)
		assert.Equal(t, "2 IPAM pool(s) available", ipv4Summary)
	})
}

func Test_MultiPoolManager_ReleaseAllCIDRs(t *testing.T) {
	var (
		tick    = 10 * time.Millisecond
		timeout = 2 * refreshPoolInterval
	)

	ipv4CIDR := netip.MustParsePrefix("10.0.50.0/24")
	ipv6CIDR := netip.MustParsePrefix("fd00:50::/96")

	currentNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeTypes.GetName()},
		Spec: ciliumv2.NodeSpec{
			IPAM: types.IPAMSpec{
				Pools: types.IPAMPoolSpec{
					Allocated: []types.IPAMPoolAllocation{
						{
							Pool: "default",
							CIDRs: []iputil.Prefix{
								iputil.PrefixFrom(ipv4CIDR),
								iputil.PrefixFrom(ipv6CIDR),
							},
						},
					},
				},
			},
		},
	}

	synctest.Test(t, func(t *testing.T) {
		var (
			jg        job.Group
			localNode k8s.LocalCiliumNodeResource
			clientset *k8sClient.FakeClientset
		)
		h := hive.New(
			k8s.ResourcesCell,
			k8sClient.FakeClientCell(),
			cell.Provide(func() *node.LocalNodeStore { return node.NewTestLocalNodeStore(node.LocalNode{}) }),
			cell.Invoke(
				func(
					jg_ job.Group,
					localNode_ k8s.LocalCiliumNodeResource,
					clientset_ *k8sClient.FakeClientset,
				) {
					jg = jg_
					localNode = localNode_
					clientset = clientset_
				},
			),
		)

		tlog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
		assert.NoError(t, h.Start(tlog, t.Context()))
		t.Cleanup(func() { h.Stop(tlog, context.Background()) })

		// create local node
		_, err := clientset.CiliumV2().CiliumNodes().Create(t.Context(), currentNode, metav1.CreateOptions{})
		assert.NoError(t, err)

		mgr := NewMultiPoolManager(MultiPoolManagerParams{
			Logger:               hivetest.Logger(t),
			IPv4Enabled:          true,
			IPv6Enabled:          true,
			CiliumNodeUpdateRate: time.Nanosecond,
			PreallocMap:          map[Pool]int{},
			Node:                 localNode,
			CNClient:             clientset.CiliumV2().CiliumNodes(),
			JobGroup:             jg,
			PoolSpecAccessors:    MultiPoolAccessor,
		})

		// Wait for manager to initialize and observe the pools
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Positive(c, mgr.capacity(IPv4))
			assert.Positive(c, mgr.capacity(IPv6))
		}, timeout, tick)

		// Allocate one IPv4 and one IPv6 IP before restore is finished. Once restore
		// is finished, updateLocalNode may release unused CIDRs immediately.
		ipv4Alloc, err := mgr.AllocateNext("test-pod-v4", "default", IPv4, false)
		assert.NoError(t, err)
		require.NotNil(t, ipv4Alloc)

		ipv6Alloc, err := mgr.AllocateNext("test-pod-v6", "default", IPv6, false)
		assert.NoError(t, err)
		require.NotNil(t, ipv6Alloc)

		// Verify both IPs are allocated
		ipv4Dump, _ := mgr.dump(IPv4)
		ipv6Dump, _ := mgr.dump(IPv6)
		assert.Len(t, ipv4Dump[PoolDefault()], 1)
		assert.Len(t, ipv6Dump[PoolDefault()], 1)

		// Mark restore as finished so that releaseExcessCIDRs can actually release CIDRs
		mgr.RestoreFinished(IPv4)
		mgr.RestoreFinished(IPv6)

		// Now release ALL IPs from the default pool (both IPv4 and IPv6)
		err = mgr.ReleaseIP(ipv4Alloc.IP, "default", IPv4, true)
		assert.NoError(t, err)

		err = mgr.ReleaseIP(ipv6Alloc.IP, "default", IPv6, true)
		assert.NoError(t, err)

		// Wait to ensure all IPs are released in internal state
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			ipv4Dump, _ := mgr.dump(IPv4)
			ipv6Dump, _ := mgr.dump(IPv6)
			// All pools should be empty now
			for pool, ips := range ipv4Dump {
				assert.Empty(c, ips, "IPv4 pool %s should be empty", pool)
			}
			for pool, ips := range ipv6Dump {
				assert.Empty(c, ips, "IPv6 pool %s should be empty", pool)
			}
		}, timeout, tick)

		// The Allocated field should be properly synchronized
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			currentNode, err = clientset.CiliumV2().CiliumNodes().Get(t.Context(), nodeTypes.GetName(), metav1.GetOptions{})
			assert.NoError(c, err)
			assert.Empty(c, currentNode.Spec.IPAM.Pools.Allocated)
		}, timeout, tick)
	})
}

// Test_MultiPoolManager_ReleaseUnusedCIDR verifies that we release all unused CIDRs.
// Specifically /32's and /128's
func Test_MultiPoolManager_ReleaseUnusedCIDR(t *testing.T) {
	logger := hivetest.Logger(t)

	fakeConfig := testConfiguration
	// disable debounce interval to trigger CiliumNode update at each test step
	fakeConfig.IPAMCiliumNodeUpdateRate = 1 * time.Nanosecond
	// disable pre-allocation
	fakeConfig.IPAMMultiPoolPreAllocation = map[string]string{}
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
	cidr1 := netip.MustParsePrefix("10.0.10.0/32")
	cidr2 := netip.MustParsePrefix("10.0.11.0/32")
	cidrv61 := netip.MustParsePrefix("fd00:10::/128")
	cidrv62 := netip.MustParsePrefix("fd00:11::/128")
	initialNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeTypes.GetName()},
		Spec: ciliumv2.NodeSpec{
			IPAM: types.IPAMSpec{
				Pools: types.IPAMPoolSpec{
					Allocated: []types.IPAMPoolAllocation{{
						Pool: "default",
						CIDRs: []iputil.Prefix{
							iputil.PrefixFrom(cidr1),
							iputil.PrefixFrom(cidr2),
							iputil.PrefixFrom(cidrv61),
							iputil.PrefixFrom(cidrv62),
						},
					}},
				},
			},
		},
	}

	// Feed initial node to the fake API so that NewMultiPoolManager returns immediately
	go fakeK8sAPI.updateNode(initialNode)

	var jg job.Group
	h := hive.New(
		cell.Invoke(func(jg_ job.Group) { jg = jg_ }),
	)

	tlog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
	assert.NoError(t, h.Start(tlog, t.Context()))
	t.Cleanup(func() { h.Stop(tlog, context.Background()) })

	preallocMap, err := ParseMultiPoolPreAllocMap(fakeConfig.IPAMMultiPoolPreAllocation)
	assert.NoError(t, err)

	mgr := NewMultiPoolManager(MultiPoolManagerParams{
		Logger:               logger,
		IPv4Enabled:          fakeConfig.EnableIPv4,
		IPv6Enabled:          fakeConfig.EnableIPv6,
		CiliumNodeUpdateRate: fakeConfig.IPAMCiliumNodeUpdateRate,
		PreallocMap:          preallocMap,
		Node:                 fakeK8sAPI,
		CNClient:             fakeK8sAPI,
		JobGroup:             jg,
		PoolSpecAccessors:    MultiPoolAccessor,
	})

	<-events // first upsert (initial node)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.True(c, mgr.isNodeSynced())
	}, time.Second, time.Millisecond)

	// Allocate one IPv4 and one IPv6 IP
	ipInCIDR1 := netip.MustParseAddr("10.0.10.0")
	_, err = mgr.AllocateIP(ipInCIDR1, "pod-a", "default", IPv4, false)
	assert.NoError(t, err)

	ipInCIDRv61 := netip.MustParseAddr("fd00:10::")
	_, err = mgr.AllocateIP(ipInCIDRv61, "pod-a", "default", IPv6, false)
	assert.NoError(t, err)

	// Mark restore finished so that releaseExcessCIDRsMultiPool() can run
	mgr.RestoreFinished(IPv4)
	mgr.RestoreFinished(IPv6)

	// Manually invoke updateLocalNode
	assert.NoError(t, mgr.updateLocalNode(context.TODO()))

	<-events // upsert generated by the update

	updated := fakeK8sAPI.currentNode()
	alloc := updated.Spec.IPAM.Pools.Allocated
	assert.Len(t, alloc, 1, "expected only one pool allocation entry")
	assert.Equal(t, "default", alloc[0].Pool)
	assert.ElementsMatch(t,

		[]iputil.Prefix{
			iputil.PrefixFrom(cidr1),
			iputil.PrefixFrom(cidrv61),
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

	// preAlloc buffer of 1 for pool "default"
	fakeConfig := testConfiguration
	// disable debounce interval to trigger CiliumNode update at each test step
	fakeConfig.IPAMMultiPoolPreAllocation = map[string]string{
		"default": "1",
	}
	// disable debounce interval to trigger CiliumNode update at each test step
	fakeConfig.IPAMCiliumNodeUpdateRate = 1 * time.Nanosecond

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
	v4Cidrs := make([]netip.Prefix, 10)
	v6Cidrs := make([]netip.Prefix, 10)
	cidrPodCIDRs := make([]iputil.Prefix, 0, 20)
	for i := range 10 {
		c4 := netip.MustParsePrefix(fmt.Sprintf("10.0.100.%d/32", i))
		v4Cidrs[i] = c4
		cidrPodCIDRs = append(cidrPodCIDRs, iputil.PrefixFrom(c4))

		c6 := netip.MustParsePrefix(fmt.Sprintf("fd00:100::%d/128", i))
		v6Cidrs[i] = c6
		cidrPodCIDRs = append(cidrPodCIDRs, iputil.PrefixFrom(c6))
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

	// Feed initial node so that NewMultiPoolManager returns immediately
	go fakeK8sAPI.updateNode(initialNode)

	var jg job.Group
	h := hive.New(
		cell.Invoke(func(jg_ job.Group) { jg = jg_ }),
	)

	tlog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
	assert.NoError(t, h.Start(tlog, t.Context()))
	t.Cleanup(func() { h.Stop(tlog, context.Background()) })

	preallocMap, err := ParseMultiPoolPreAllocMap(fakeConfig.IPAMMultiPoolPreAllocation)
	assert.NoError(t, err)

	mgr := NewMultiPoolManager(MultiPoolManagerParams{
		Logger:               logger,
		IPv4Enabled:          fakeConfig.EnableIPv4,
		IPv6Enabled:          fakeConfig.EnableIPv6,
		CiliumNodeUpdateRate: fakeConfig.IPAMCiliumNodeUpdateRate,
		PreallocMap:          preallocMap,
		Node:                 fakeK8sAPI,
		CNClient:             fakeK8sAPI,
		JobGroup:             jg,
		PoolSpecAccessors:    MultiPoolAccessor,
	})

	<-events // first upsert (initial node)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.True(c, mgr.isNodeSynced())
	}, time.Second, time.Millisecond)

	// Allocate 5 IPv4 and 5 IPv6 IPs
	for i := range 5 {
		ip4 := netip.MustParseAddr(fmt.Sprintf("10.0.100.%d", i))
		_, err := mgr.AllocateIP(ip4, fmt.Sprintf("pod4-%d", i), "default", IPv4, false)
		assert.NoError(t, err)

		ip6 := netip.MustParseAddr(fmt.Sprintf("fd00:100::%d", i))
		_, err = mgr.AllocateIP(ip6, fmt.Sprintf("pod6-%d", i), "default", IPv6, false)
		assert.NoError(t, err)
	}

	// Mark restore finished so release code can run
	mgr.RestoreFinished(IPv4)
	mgr.RestoreFinished(IPv6)
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
		remaining[c.String()] = struct{}{}
	}
	for i := range 5 {
		assert.Contains(t, remaining, v4Cidrs[i].String(), "in-use CIDR %s should not be released", v4Cidrs[i].String())
		assert.Contains(t, remaining, v6Cidrs[i].String(), "in-use CIDR %s should not be released", v6Cidrs[i].String())
	}
}

func Test_LocalNodeCIDRsSyncer(t *testing.T) {
	var (
		tick    = 10 * time.Millisecond
		timeout = 5 * time.Second
	)

	defaultIPv4CIDR1 := netip.MustParsePrefix("10.0.22.0/24")
	defaultIPv6CIDR1 := netip.MustParsePrefix("fd00:22::/96")
	marsIPv4CIDR1 := netip.MustParsePrefix("10.0.11.0/27")
	marsIPv6CIDR1 := netip.MustParsePrefix("fd00:11::/123")
	jupiterIPv4CIDR := netip.MustParsePrefix("192.168.1.0/16")
	jupiterIPv6CIDR := netip.MustParsePrefix("fc00:33::/96")

	currentNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeTypes.GetName()},
		Spec: ciliumv2.NodeSpec{
			IPAM: types.IPAMSpec{
				Pools: types.IPAMPoolSpec{
					Allocated: []types.IPAMPoolAllocation{
						{
							Pool: "default",
							CIDRs: []iputil.Prefix{
								iputil.PrefixFrom(defaultIPv4CIDR1),
								iputil.PrefixFrom(defaultIPv6CIDR1),
							},
						},
						{
							Pool: "mars",
							CIDRs: []iputil.Prefix{
								iputil.PrefixFrom(marsIPv4CIDR1),
								iputil.PrefixFrom(marsIPv6CIDR1),
							},
						},
					},
				},
			},
		},
	}

	var (
		jg             job.Group
		localNode      k8s.LocalCiliumNodeResource
		localNodeStore *node.LocalNodeStore
		clientset      *k8sClient.FakeClientset
	)
	h := hive.New(
		k8s.ResourcesCell,
		k8sClient.FakeClientCell(),
		cell.Provide(func() *node.LocalNodeStore { return node.NewTestLocalNodeStore(node.LocalNode{}) }),
		cell.Invoke(
			func(
				jg_ job.Group,
				localNode_ k8s.LocalCiliumNodeResource,
				localNodeStore_ *node.LocalNodeStore,
				clientset_ *k8sClient.FakeClientset,
			) {
				jg = jg_
				localNode = localNode_
				localNodeStore = localNodeStore_
				clientset = clientset_
			},
		),
	)

	tlog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
	assert.NoError(t, h.Start(tlog, t.Context()))
	t.Cleanup(func() { h.Stop(tlog, context.Background()) })

	// start syncing local node allocation CIDRs
	startLocalNodeAllocCIDRsSync(true, true, jg, localNode, localNodeStore)

	// create local node
	currentNode, err := clientset.CiliumV2().CiliumNodes().Create(t.Context(), currentNode, metav1.CreateOptions{})
	assert.NoError(t, err)

	// Check that the local node store has been updated
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		localNode, err := localNodeStore.Get(t.Context())
		assert.NoError(c, err)
		assert.Equalf(c,
			nodeTypes.PrefixFrom(defaultIPv4CIDR1), localNode.IPv4AllocCIDR,
			"IPv4 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv4SecondaryAllocCIDRs, []nodeTypes.Prefix{nodeTypes.PrefixFrom(marsIPv4CIDR1)},
			"IPv4 secondary allocation CIDRs do not match",
		)
		assert.Equalf(c,
			nodeTypes.PrefixFrom(defaultIPv6CIDR1), localNode.IPv6AllocCIDR,
			"IPv6 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv6SecondaryAllocCIDRs, []nodeTypes.Prefix{nodeTypes.PrefixFrom(marsIPv6CIDR1)},
			"IPv6 secondary allocation CIDRs do not match",
		)
	}, timeout, tick)

	// assign additional CIDRs from another pool
	currentNode.Spec.IPAM.Pools.Allocated = append(currentNode.Spec.IPAM.Pools.Allocated,
		types.IPAMPoolAllocation{
			Pool: "jupiter",
			CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(jupiterIPv4CIDR),
				iputil.PrefixFrom(jupiterIPv6CIDR),
			},
		},
	)

	// update local node
	currentNode, err = clientset.CiliumV2().CiliumNodes().Update(t.Context(), currentNode, metav1.UpdateOptions{})
	assert.NoError(t, err)

	// Check that the local node store has been updated
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		localNode, err := localNodeStore.Get(t.Context())
		assert.NoError(c, err)
		assert.Equalf(c,
			nodeTypes.PrefixFrom(defaultIPv4CIDR1), localNode.IPv4AllocCIDR,
			"IPv4 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv4SecondaryAllocCIDRs, []nodeTypes.Prefix{nodeTypes.PrefixFrom(marsIPv4CIDR1), nodeTypes.PrefixFrom(jupiterIPv4CIDR)},
			"IPv4 secondary allocation CIDRs do not match",
		)
		assert.Equalf(c,
			nodeTypes.PrefixFrom(defaultIPv6CIDR1), localNode.IPv6AllocCIDR,
			"IPv6 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv6SecondaryAllocCIDRs, []nodeTypes.Prefix{nodeTypes.PrefixFrom(marsIPv6CIDR1), nodeTypes.PrefixFrom(jupiterIPv6CIDR)},
			"IPv6 secondary allocation CIDRs do not match",
		)
	}, timeout, tick)

	// remove all additional CIDRs from mars and jupiter pool
	currentNode.Spec.IPAM.Pools.Allocated = []types.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []iputil.Prefix{
				iputil.PrefixFrom(defaultIPv4CIDR1),
				iputil.PrefixFrom(defaultIPv6CIDR1),
			},
		},
	}

	// update local node
	_, err = clientset.CiliumV2().CiliumNodes().Update(t.Context(), currentNode, metav1.UpdateOptions{})
	assert.NoError(t, err)

	// Check that the local node store has been updated
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		localNode, err := localNodeStore.Get(t.Context())
		assert.NoError(c, err)
		assert.Equalf(c,
			nodeTypes.PrefixFrom(defaultIPv4CIDR1), localNode.IPv4AllocCIDR,
			"IPv4 primary allocation CIDR do not match",
		)
		assert.Empty(c,
			localNode.IPv4SecondaryAllocCIDRs,
			"IPv4 secondary allocation CIDRs do not match",
		)
		assert.Equalf(c,
			nodeTypes.PrefixFrom(defaultIPv6CIDR1), localNode.IPv6AllocCIDR,
			"IPv6 primary allocation CIDR do not match",
		)
		assert.Empty(c,
			localNode.IPv6SecondaryAllocCIDRs,
			"IPv6 secondary allocation CIDRs do not match",
		)
	}, timeout, tick)

	assert.NoError(t, h.Stop(tlog, t.Context()))
}

func Test_MultiPoolManager_UpdateNodeRetries(t *testing.T) {
	fixture := func(t *testing.T, node *ciliumv2.CiliumNode, setReactor func(cs *k8sClient.FakeClientset)) *k8sClient.FakeClientset {
		nodeTypes.SetName(node.Name)

		var (
			jg        job.Group
			localNode k8s.LocalCiliumNodeResource
			clientset *k8sClient.FakeClientset
		)
		h := hive.New(
			k8sClient.FakeClientCell(),
			k8s.ResourcesCell,
			cell.Invoke(
				func(cs *k8sClient.FakeClientset) {
					setReactor(cs)
				},
				func(
					jg_ job.Group,
					localNode_ k8s.LocalCiliumNodeResource,
					clientset_ *k8sClient.FakeClientset,
				) {
					jg = jg_
					localNode = localNode_
					clientset = clientset_
				},
			),
		)

		tlog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
		require.NoError(t, h.Start(tlog, t.Context()))
		t.Cleanup(func() { h.Stop(tlog, context.Background()) })

		_, err := clientset.CiliumV2().CiliumNodes().Create(t.Context(), node.DeepCopy(), metav1.CreateOptions{})
		assert.NoError(t, err)

		mgr := NewMultiPoolManager(MultiPoolManagerParams{
			Logger:               hivetest.Logger(t),
			IPv4Enabled:          true,
			CiliumNodeUpdateRate: time.Millisecond,
			PreallocMap:          preAllocatePerPool{},
			Node:                 localNode,
			CNClient:             clientset.CiliumV2().CiliumNodes(),
			JobGroup:             jg,
			PoolSpecAccessors:    MultiPoolAccessor,
		})
		require.NotNil(t, mgr)

		return clientset
	}

	t.Run("update", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-node",
			},
			Spec: ciliumv2.NodeSpec{
				IPAM: types.IPAMSpec{
					Pools: types.IPAMPoolSpec{
						Requested: []types.IPAMPoolRequest{
							{
								Pool:   "default",
								Needed: types.IPAMPoolDemand{IPv4Addrs: 99},
							},
						},
					},
				},
			},
		}

		var updates atomic.Int32
		updateReactor := func(cs *k8sClient.FakeClientset) {
			cs.CiliumFakeClientset.PrependReactor("update", "ciliumnodes", func(action k8sTesting.Action) (bool, runtime.Object, error) {
				if action.GetSubresource() != "" {
					return false, nil, nil
				}

				if updates.Add(1) == 1 {
					return true, nil, k8sErrors.NewConflict(
						schema.GroupResource{
							Group:    ciliumv2.CustomResourceDefinitionGroup,
							Resource: ciliumv2.CNPluralName,
						},
						node.Name,
						errors.New("update refused by unit test"),
					)
				}
				return false, nil, nil
			})
		}

		synctest.Test(t, func(t *testing.T) {
			clientset := fixture(t, node, updateReactor)

			// wait for the manager to retry the update after the conflict error
			//
			// the timeout is set to 2xrefreshPoolInterval so that updateLocalNode
			// has a chance to be run again from the job.Timer.
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.GreaterOrEqual(c, updates.Load(), int32(2))
			}, 2*time.Minute, 10*time.Millisecond)

			updatedNode, err := clientset.CiliumV2().CiliumNodes().Get(t.Context(), node.Name, metav1.GetOptions{})
			assert.NoError(t, err)
			assert.Empty(t, updatedNode.Spec.IPAM.Pools.Requested)
		})
	})

	t.Run("updateStatus", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node-status",
			},
			Status: ciliumv2.NodeStatus{
				IPAM: types.IPAMStatus{
					Used: types.AllocationMap{
						iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")): types.AllocationIP{Resource: "pod-a"},
					},
				},
			},
		}

		var updateStatuses atomic.Int32
		updateStatusReactor := func(cs *k8sClient.FakeClientset) {
			cs.CiliumFakeClientset.PrependReactor("update", "ciliumnodes", func(action k8sTesting.Action) (bool, runtime.Object, error) {
				if action.GetSubresource() != "status" {
					return false, nil, nil
				}

				if updateStatuses.Add(1) == 1 {
					return true, nil, k8sErrors.NewConflict(
						schema.GroupResource{
							Group:    ciliumv2.CustomResourceDefinitionGroup,
							Resource: ciliumv2.CNPluralName,
						},
						node.Name,
						errors.New("update refused by unit test"),
					)
				}
				return false, nil, nil
			})
		}

		synctest.Test(t, func(t *testing.T) {
			clientset := fixture(t, node, updateStatusReactor)

			// wait for the manager to retry the update after the conflict error
			//
			// the timeout is set to 2xrefreshPoolInterval so that updateLocalNode
			// has a chance to be run again from the job.Timer.
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.GreaterOrEqual(c, updateStatuses.Load(), int32(2))
			}, 2*time.Minute, 10*time.Millisecond)

			updatedNode, err := clientset.CiliumV2().CiliumNodes().Get(t.Context(), node.Name, metav1.GetOptions{})
			assert.NoError(t, err)
			assert.Empty(t, updatedNode.Status.IPAM.Used)
		})
	})
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
	mutex  lock.Mutex
	node   *ciliumv2.CiliumNode
	c      chan resource.Event[*ciliumv2.CiliumNode]
	synced bool

	onUpsertEvent func(err error)
	onDeleteEvent func(err error)
}

func (k *fakeK8sCiliumNodeAPIResource) Create(ctx context.Context, ciliumNode *ciliumv2.CiliumNode, opts v1.CreateOptions) (*ciliumv2.CiliumNode, error) {
	panic("unimplemented")
}

func (f *fakeK8sCiliumNodeAPIResource) Update(ctx context.Context, ciliumNode *ciliumv2.CiliumNode, _ metav1.UpdateOptions) (*ciliumv2.CiliumNode, error) {
	err := f.updateNode(ciliumNode)
	return ciliumNode, err
}

func (k *fakeK8sCiliumNodeAPIResource) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	panic("unimplemented")
}

func (k *fakeK8sCiliumNodeAPIResource) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	panic("unimplemented")
}

func (k *fakeK8sCiliumNodeAPIResource) Get(ctx context.Context, name string, opts v1.GetOptions) (*ciliumv2.CiliumNode, error) {
	panic("unimplemented")
}

func (k *fakeK8sCiliumNodeAPIResource) List(ctx context.Context, opts v1.ListOptions) (*ciliumv2.CiliumNodeList, error) {
	panic("unimplemented")
}

func (k *fakeK8sCiliumNodeAPIResource) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	panic("unimplemented")
}

func (k *fakeK8sCiliumNodeAPIResource) Patch(ctx context.Context, name string, pt k8sTypes.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *ciliumv2.CiliumNode, err error) {
	panic("unimplemented")
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

	// close events channel when the context is done
	go func() {
		<-ctx.Done()
		close(f.c)
	}()

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

	sendSync := !f.synced
	if sendSync {
		f.synced = true
	}
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

	if sendSync {
		c <- resource.Event[*ciliumv2.CiliumNode]{
			Kind: resource.Sync,
			Done: func(error) {},
		}
	}

	return nil
}

func TestAllocateNext_SkipMasquerade(t *testing.T) {
	db := statedb.New()
	poolsTbl, err := podippool.NewTable(db)
	require.NoError(t, err)

	insertPool(t, db, poolsTbl, "default", false)
	insertPool(t, db, poolsTbl, "blue", false)
	insertPool(t, db, poolsTbl, "red", true) // skip-masquerade annotation
	insertPool(t, db, poolsTbl, "green", false)

	// onlyMasqueradeDefaultPool = true, non-default pool
	mgr := createSkipMasqTestManager(t, db, poolsTbl, true)
	res, err := mgr.AllocateNextWithoutSyncUpstream("ns/pod", "blue")
	require.NoError(t, err)
	require.True(t, res.SkipMasquerade, "SkipMasquerade should be true for non-default pools when onlyMasqueradeDefaultPool is set")

	// onlyMasqueradeDefaultPool = true, default pool
	res, err = mgr.AllocateNextWithoutSyncUpstream("ns/pod", "default")
	require.NoError(t, err)
	require.False(t, res.SkipMasquerade, "default pool should always be masqueraded even if global flag set")

	// onlyMasqueradeDefaultPool = false but pool annotated with skip-masquerade
	mgr = createSkipMasqTestManager(t, db, poolsTbl, false)
	res, err = mgr.AllocateNextWithoutSyncUpstream("ns/pod", "red")
	require.NoError(t, err)
	require.True(t, res.SkipMasquerade, "SkipMasquerade should be true based on pool annotation")

	// honour annotation on default pool also
	insertPool(t, db, poolsTbl, "default", true)
	mgr = createSkipMasqTestManager(t, db, poolsTbl, false)
	res, err = mgr.AllocateNextWithoutSyncUpstream("ns/pod", "default")
	require.NoError(t, err)
	require.True(t, res.SkipMasquerade, "default pool should not be masqueraded if annotation set")

	// neither flag nor annotation set
	mgr = createSkipMasqTestManager(t, db, poolsTbl, false)
	res, err = mgr.AllocateNextWithoutSyncUpstream("ns/pod", "green")
	require.NoError(t, err)
	require.False(t, res.SkipMasquerade, "SkipMasquerade should default to false")
}

func TestMultiPoolManagerUpdatesFirstLastIPSettingsBeforeAllocation(t *testing.T) {
	logger := hivetest.Logger(t)
	mgr := &MultiPoolManager{
		logger:       logger,
		ipv4Enabled:  true,
		pools:        map[Pool]*poolPair{},
		poolsUpdated: make(chan struct{}, 1),
		pendingIPsPerPool: newPendingAllocationsPerPool(
			logger,
		),
		skipMasqueradeForPool: func(Pool) (bool, error) {
			return false, nil
		},
	}

	prefix := iputil.PrefixFrom(netip.MustParsePrefix("10.20.0.0/30"))
	lastIP := netip.MustParseAddr("10.20.0.3")

	mgr.upsertPoolLocked("default", []iputil.Prefix{prefix}, false, false, false)
	_, err := mgr.AllocateIP(lastIP, "pod-a", "default", IPv4, false)
	require.Error(t, err)

	mgr.upsertPoolLocked("default", []iputil.Prefix{prefix}, false, true, false)
	result, err := mgr.AllocateIP(lastIP, "pod-a", "default", IPv4, false)
	require.NoError(t, err)
	require.Equal(t, lastIP, result.IP)
}

func TestMultiPoolManagerWaitForAllPools(t *testing.T) {
	poolA, poolB := Pool("pool-a"), Pool("pool-b")

	synctest.Test(t, func(t *testing.T) {
		mgr := &MultiPoolManager{
			logger:                 hivetest.Logger(t),
			ipv4Enabled:            true,
			preallocatedIPsPerPool: preAllocatePerPool{poolA: 8, poolB: 0},
			pools:                  map[Pool]*poolPair{},
			poolsUpdated:           make(chan struct{}, 1),
		}

		var wg sync.WaitGroup
		wg.Go(func() {
			mgr.waitForAllPools()
		})

		// wait until waitForAllPools is blocked on poolA
		synctest.Wait()

		// unblock waitForAllPools by adding poolA, but not poolB (which has zero preallocation)
		mgr.poolsMutex.Lock()
		mgr.upsertPoolLocked(poolA, []iputil.Prefix{
			iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/30")),
		}, false, false, false)
		mgr.poolsMutex.Unlock()

		// wait for waitForAllPools to unblock
		wg.Wait()

		mgr.poolsMutex.Lock()
		require.Contains(t, mgr.pools, poolA)
		require.NotContains(t, mgr.pools, poolB)
		mgr.poolsMutex.Unlock()
	})
}

func Test_multiPoolManager_staticIPStatus(t *testing.T) {
	newNode := func(tags map[string]string, assigned netip.Addr) *ciliumv2.CiliumNode {
		return &ciliumv2.CiliumNode{
			Spec: ciliumv2.NodeSpec{
				IPAM: types.IPAMSpec{StaticIPTags: tags},
			},
			Status: ciliumv2.NodeStatus{
				IPAM: types.IPAMStatus{AssignedStaticIP: iputil.AddrFrom(assigned)},
			},
		}
	}

	tests := []struct {
		name                  string
		node                  *ciliumv2.CiliumNode
		wantRequestedStaticIP bool
		wantAssignedStaticIP  netip.Addr
	}{
		{
			name:                  "nil node",
			node:                  nil,
			wantRequestedStaticIP: false,
			wantAssignedStaticIP:  netip.Addr{},
		},
		{
			name:                  "no static IP requested",
			node:                  newNode(nil, netip.Addr{}),
			wantRequestedStaticIP: false,
			wantAssignedStaticIP:  netip.Addr{},
		},
		{
			name:                  "static IP requested but not yet assigned",
			node:                  newNode(map[string]string{"env": "prod"}, netip.Addr{}),
			wantRequestedStaticIP: true,
			wantAssignedStaticIP:  netip.Addr{},
		},
		{
			name:                  "static IP requested and assigned",
			node:                  newNode(map[string]string{"env": "prod"}, netip.MustParseAddr("1.2.3.4")),
			wantRequestedStaticIP: true,
			wantAssignedStaticIP:  netip.MustParseAddr("1.2.3.4"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &MultiPoolManager{node: tt.node}
			requested, assigned := mgr.staticIPStatus()
			assert.Equal(t, tt.wantRequestedStaticIP, requested)
			assert.Equal(t, tt.wantAssignedStaticIP, assigned)
		})
	}
}

func insertPool(t *testing.T, db *statedb.DB, tbl statedb.RWTable[podippool.LocalPodIPPool], name string, skipMasq bool, allowFirstAndLastIPs ...bool) {
	t.Helper()
	ann := map[string]string{}
	if skipMasq {
		ann[annotation.IPAMSkipMasquerade] = "true"
	}
	var allowFirstIP, allowLastIP bool
	if len(allowFirstAndLastIPs) > 0 {
		allowFirstIP = allowFirstAndLastIPs[0]
	}
	if len(allowFirstAndLastIPs) > 1 {
		allowLastIP = allowFirstAndLastIPs[1]
	}

	poolObj := podippool.LocalPodIPPool{
		CiliumPodIPPool: &ciliumv2.CiliumPodIPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Annotations: ann,
			},
			Spec: ciliumv2.IPPoolSpec{
				AllowFirstIP: allowFirstIP,
				AllowLastIP:  allowLastIP,
			},
		},
		UpdatedAt: time.Now(),
	}

	w := db.WriteTxn(tbl)
	tbl.Insert(w, poolObj)
	w.Commit()
}

func createSkipMasqTestManager(t *testing.T, db *statedb.DB, pools statedb.Table[podippool.LocalPodIPPool], onlyMasqDefault bool) Allocator {
	t.Helper()

	fakeConfig := testConfiguration
	fakeConfig.IPAMMultiPoolPreAllocation = map[string]string{}

	initialNode := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: nodeTypes.GetName()},
		Spec: ciliumv2.NodeSpec{
			IPAM: types.IPAMSpec{
				Pools: types.IPAMPoolSpec{
					Allocated: []types.IPAMPoolAllocation{
						{Pool: "default", CIDRs: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24"))}},
						{Pool: "blue", CIDRs: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.1.0/24"))}},
						{Pool: "red", CIDRs: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.2.0/24"))}},
						{Pool: "green", CIDRs: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.3.0/24"))}},
					},
				},
			},
		},
	}

	var (
		jg             job.Group
		localNode      k8s.LocalCiliumNodeResource
		localNodeStore *node.LocalNodeStore
		clientset      *k8sClient.FakeClientset
	)
	h := hive.New(
		k8s.ResourcesCell,
		k8sClient.FakeClientCell(),
		cell.Provide(func() *node.LocalNodeStore { return node.NewTestLocalNodeStore(node.LocalNode{}) }),
		cell.Invoke(
			func(
				jg_ job.Group,
				localNode_ k8s.LocalCiliumNodeResource,
				localNodeStore_ *node.LocalNodeStore,
				clientset_ *k8sClient.FakeClientset,
			) {
				jg = jg_
				localNode = localNode_
				localNodeStore = localNodeStore_
				clientset = clientset_
			},
		),
	)

	tlog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
	assert.NoError(t, h.Start(tlog, t.Context()))
	t.Cleanup(func() { h.Stop(tlog, t.Context()) })

	// create local node
	_, err := clientset.CiliumV2().CiliumNodes().Create(t.Context(), initialNode, metav1.CreateOptions{})
	assert.NoError(t, err)

	v4Alloc, _, err := newMultiPoolAllocators(t.Context(), MultiPoolAllocatorParams{
		Logger:                    hivetest.Logger(t),
		IPv4Enabled:               fakeConfig.EnableIPv4,
		IPv6Enabled:               fakeConfig.EnableIPv6,
		CiliumNodeUpdateRate:      fakeConfig.IPAMCiliumNodeUpdateRate,
		PreAllocPools:             fakeConfig.IPAMMultiPoolPreAllocation,
		Node:                      localNode,
		LocalNodeStore:            localNodeStore,
		CNClient:                  clientset.CiliumV2().CiliumNodes(),
		JobGroup:                  jg,
		DB:                        db,
		PodIPPools:                pools,
		OnlyMasqueradeDefaultPool: onlyMasqDefault,
	})
	require.NoError(t, err)

	return v4Alloc
}

// eniHarness drives a MultiPoolManager the way the ENI agent does, for the
// tests of cilium/cilium#47910 (https://github.com/cilium/cilium/issues/47910):
// the pool CIDRs are read from the operator-owned Status.ENI prefixes, and the
// agent publishes its in-use CIDRs to Spec.IPAM.Pools. CiliumNode events and
// sync rounds are invoked synchronously, so the tests are deterministic.
type eniHarness struct {
	t   *testing.T
	mgr *MultiPoolManager
	// published is what the agent last wrote to Spec.IPAM.Pools.
	published types.IPAMPoolSpec
	// apiserver is the Spec.IPAM.Pools that a GET from the operator
	// returns. It lags behind published until land is called.
	apiserver types.IPAMPoolSpec
	owner     int

	// The fields below are only used by the release handshake tests.
	//
	// server is Status.IPAM.ReleaseCIDRs in the apiserver.
	server types.CIDRReleaseStatusMap
	// version is the resource version of the CiliumNode in the apiserver.
	version int
	// enis is the Status.ENI last written by the operator.
	enis map[string]awsTypes.ENI
	// inflight is the agent's last status write, until land is called.
	inflight *inflightStatus
}

const eniPreAllocate = 8 // ENI default pre-allocate

func newENIHarness(t *testing.T) *eniHarness {
	h := &eniHarness{t: t}
	logger := hivetest.Logger(t)

	// Mirrors poolAccessor in pkg/aws/agent/pools.go for delegated /28
	// prefixes. pkg/aws/agent imports pkg/ipam, so it cannot be used here.
	accessor := PoolSpecAccessors{
		FromResource: func(node *ciliumv2.CiliumNode) (types.IPAMPoolSpec, bool) {
			pools := types.IPAMPoolSpec{
				Requested: node.Spec.IPAM.Pools.Requested,
				Allocated: node.Spec.IPAM.Pools.Allocated,
			}
			var cidrs []iputil.Prefix
			for _, eni := range node.Status.ENI.ENIs {
				cidrs = append(cidrs, eni.Prefixes...)
			}
			if len(cidrs) == 0 {
				return pools, false
			}
			pools.Allocated = []types.IPAMPoolAllocation{{
				Pool:         defaults.IPAMDefaultIPPool,
				AllowFirstIP: true,
				AllowLastIP:  true,
				CIDRs:        cidrs,
			}}
			return pools, true
		},
		// Record what the agent publishes instead of writing it through a
		// client: in ENI mode it is not read back as pool input.
		ToResource: func(_ *ciliumv2.CiliumNode, spec types.IPAMPoolSpec) bool {
			h.published = spec
			return false
		},
	}

	h.mgr = &MultiPoolManager{
		logger:                 logger,
		ipv4Enabled:            true,
		preallocatedIPsPerPool: preAllocatePerPool{},
		pendingIPsPerPool:      newPendingAllocationsPerPool(logger),
		pools:                  map[Pool]*poolPair{},
		poolsUpdated:           make(chan struct{}, 1),
		staticIPUpdated:        make(chan struct{}, 1),
		finishedRestore:        map[Family]bool{IPv4: true},
		k8sUpdater:             job.NewTrigger(),
		localNodeUpdateFn:      func() {},
		nodeSynced:             true,
		poolsAccessor:          accessor,
		linearPreAlloc:         true, // as in cloud_multipool.go
		skipMasqueradeForPool:  func(Pool) (bool, error) { return false, nil },
	}
	return h
}

// operatorWrites simulates the operator writing Status.ENI with the given
// prefixes on a single ENI, delivered to the agent as a CiliumNode event.
func (h *eniHarness) operatorWrites(prefixes ...string) {
	h.t.Helper()
	pfx := make([]iputil.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		pfx = append(pfx, iputil.PrefixFrom(netip.MustParsePrefix(p)))
	}
	h.operatorWritesENIs(map[string]awsTypes.ENI{"eni-1": {ID: "eni-1", Prefixes: pfx}})
}

func (h *eniHarness) operatorWritesENIs(enis map[string]awsTypes.ENI) {
	h.t.Helper()
	h.version++
	h.enis = enis
	node := &ciliumv2.CiliumNode{ObjectMeta: metav1.ObjectMeta{
		Name:            "node-eni",
		ResourceVersion: strconv.Itoa(h.version),
	}}
	node.Spec.IPAM.PreAllocate = eniPreAllocate
	node.Status.ENI.ENIs = enis
	node.Status.IPAM.ReleaseCIDRs = h.server.DeepCopy()
	h.mgr.ciliumNodeUpdated(node)
}

// agentEchoWrites simulates a CiliumNode event with an empty Status.ENI. The
// accessor then falls back to Spec.IPAM.Pools, i.e. what the agent published.
func (h *eniHarness) agentEchoWrites() {
	h.t.Helper()
	node := &ciliumv2.CiliumNode{ObjectMeta: metav1.ObjectMeta{Name: "node-eni"}}
	node.Spec.IPAM.PreAllocate = eniPreAllocate
	node.Spec.IPAM.Pools = *h.published.DeepCopy()
	h.mgr.ciliumNodeUpdated(node)
}

func (h *eniHarness) pool() *cidrPool {
	return h.mgr.pools[Pool(defaults.IPAMDefaultIPPool)].v4
}

func (h *eniHarness) removed(prefix string) bool {
	h.mgr.poolsMutex.Lock()
	defer h.mgr.poolsMutex.Unlock()
	_, ok := h.pool().removed[netip.MustParsePrefix(prefix)]
	return ok
}

func (h *eniHarness) publishedCIDRs() []netip.Prefix {
	var out []netip.Prefix
	for _, alloc := range h.published.Allocated {
		for _, c := range alloc.CIDRs {
			out = append(out, c.Prefix)
		}
	}
	return out
}

// sync runs one agent CiliumNode sync round (multi-pool-cilium-node-updater).
func (h *eniHarness) sync() {
	h.t.Helper()
	require.NoError(h.t, h.mgr.updateLocalNode(h.t.Context()))
}

// land makes the agent's last write visible to GETs from the operator. A
// status write based on an outdated resource version is dropped, as the
// apiserver rejects it with a conflict. A status write that lands is
// delivered back to the agent.
func (h *eniHarness) land() {
	h.apiserver = *h.published.DeepCopy()
	if inflight := h.inflight; inflight != nil {
		h.inflight = nil
		if inflight.version == strconv.Itoa(h.version) {
			h.server = inflight.releaseCIDRs
			h.operatorWritesENIs(h.enis)
		}
	}
}

func (h *eniHarness) allocateNext() (netip.Addr, error) {
	h.owner++
	res, err := h.mgr.AllocateNext(fmt.Sprintf("pod-%d", h.owner), Pool(defaults.IPAMDefaultIPPool), IPv4, false)
	if err != nil {
		return netip.Addr{}, err
	}
	return res.IP, nil
}

func (h *eniHarness) mustAllocate(n int) []netip.Addr {
	h.t.Helper()
	addrs := make([]netip.Addr, 0, n)
	for range n {
		addr, err := h.allocateNext()
		require.NoError(h.t, err, h.state())
		addrs = append(addrs, addr)
	}
	return addrs
}

func (h *eniHarness) release(addrs ...netip.Addr) {
	h.t.Helper()
	for _, addr := range addrs {
		require.NoError(h.t, h.mgr.ReleaseIP(addr, Pool(defaults.IPAMDefaultIPPool), IPv4, false))
	}
}

// allocateEventually retries a single pod allocation like the CNI does,
// with an agent sync round between attempts, and returns the last error.
func (h *eniHarness) allocateEventually(rounds int) (netip.Addr, error) {
	h.t.Helper()
	var err error
	h.owner++
	owner := fmt.Sprintf("pending-pod-%d", h.owner)
	for range rounds {
		var res *AllocationResult
		res, err = h.mgr.AllocateNext(owner, Pool(defaults.IPAMDefaultIPPool), IPv4, false)
		if err == nil {
			return res.IP, nil
		}
		h.sync()
	}
	return netip.Addr{}, err
}

func (h *eniHarness) state() string {
	h.mgr.poolsMutex.Lock()
	defer h.mgr.poolsMutex.Unlock()
	pool, ok := h.mgr.pools[Pool(defaults.IPAMDefaultIPPool)]
	if !ok || pool.v4 == nil {
		return "no pool"
	}
	return fmt.Sprintf("%s published.Allocated=%v published.Requested=%v",
		cidrPoolState(pool.v4), h.published.Allocated, h.published.Requested)
}

// TestMultiPoolManagerENIRegainsPrefixDroppedAndReadded reproduces the ENI
// mode sequence of cilium/cilium#47910: pods allocate from P2, one operator
// write drops P2 from Status.ENI, a later write re-adds it. P2 is published
// as allocated and has free IPs, so pod allocation must succeed again.
//   - "only re-added prefix": no spare prefix, the removed mark was the
//     only problem.
//   - "spare released prefix": P3 is released but still attached, and the
//     free IPs of the removed P2 also prevented reclaiming it.
func TestMultiPoolManagerENIRegainsPrefixDroppedAndReadded(t *testing.T) {
	const (
		p1 = "10.0.0.0/28"
		p2 = "10.0.0.16/28"
		p3 = "10.0.0.32/28"
	)

	tests := []struct {
		name      string
		withP2    []string // Status.ENI prefixes, in ENI order
		withoutP2 []string // Status.ENI prefixes of the write that drops P2
	}{
		{name: "only re-added prefix", withP2: []string{p1, p2}, withoutP2: []string{p1}},
		{name: "spare released prefix", withP2: []string{p1, p2, p3}, withoutP2: []string{p1, p3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newENIHarness(t)

			// P1 is filled and 4 pods land on P2.
			h.operatorWrites(tt.withP2...)
			addrs := h.mustAllocate(20)
			require.True(t, netip.MustParsePrefix(p2).Contains(addrs[19]), "precondition: pods allocated from %s", p2)
			// Sync round: demand 20+8=28, so an unused P3 is released (still attached).
			h.sync()

			// One operator write drops P2 from Status.ENI ...
			h.operatorWrites(tt.withoutP2...)
			h.sync()
			// ... and a later write re-adds the same /28.
			h.operatorWrites(tt.withP2...)
			h.sync()

			_, err := h.allocateEventually(5)
			require.NoError(t, err,
				"%s is re-advertised with 12 free IPs: allocation must eventually succeed; %s", p2, h.state())
		})
	}
}

// TestMultiPoolManagerENIReclaimsAfterGhostPrefix reproduces the "ghost /28"
// sequence of cilium/cilium#47910: a 198.18.0.0/28 prefix shows up in
// Status.ENI for one write, a pod is allocated from it, then it disappears
// while a real prefix is attached. The free IPs of the removed ghost must
// not count as capacity, or the real prefix is released and never
// reclaimed.
func TestMultiPoolManagerENIReclaimsAfterGhostPrefix(t *testing.T) {
	h := newENIHarness(t)

	const (
		p1    = "10.0.0.0/28"
		p2    = "10.0.0.16/28"
		ghost = "198.18.0.0/28"
	)

	// P1 is full.
	h.operatorWrites(p1)
	h.mustAllocate(16)
	h.sync()

	// The ghost /28 appears for one write and a pod lands on it.
	h.operatorWrites(p1, ghost)
	addrs := h.mustAllocate(1)
	require.True(t, netip.MustParsePrefix(ghost).Contains(addrs[0]), "precondition: pod allocated from ghost %s", ghost)
	h.sync()

	// The next write removes the ghost and attaches the real P2.
	h.operatorWrites(p1, p2)
	h.sync()

	_, err := h.allocateEventually(5)
	require.NoError(t, err,
		"%s (16 free IPs) is attached, only the removed ghost %s holds free IPs: allocation must eventually succeed; %s",
		p2, ghost, h.state())
}

// TestMultiPoolManagerENIRegainsRemovedPrefix checks that in ENI mode a
// prefix X that was removed while in use becomes allocatable again as soon as
// the operator re-advertises it in Status.ENI, without an agent sync round.
func TestMultiPoolManagerENIRegainsRemovedPrefix(t *testing.T) {
	h := newENIHarness(t)

	const (
		p1 = "10.0.0.0/28"
		x  = "10.0.0.16/28"
	)

	// P1 is filled and 4 pods land on X.
	h.operatorWrites(p1, x)
	h.mustAllocate(20)
	h.sync()

	// The operator drops X from Status.ENI: X is removed but kept as in use.
	h.operatorWrites(p1)
	h.sync()
	require.True(t, h.removed(x), "precondition: %s removed; %s", x, h.state())

	h.operatorWrites(p1, x)
	require.False(t, h.removed(x), "re-advertised %s must be regained; %s", x, h.state())
	addr, err := h.allocateNext()
	require.NoError(t, err, "%s has 12 free IPs; %s", x, h.state())
	require.True(t, netip.MustParsePrefix(x).Contains(addr), "allocated %s, want an IP from %s", addr, x)
}

// TestMultiPoolManagerENIFallbackDoesNotRegain checks that a CiliumNode
// event with an empty Status.ENI does not regain a removed prefix X: the
// accessor then falls back to Spec.IPAM.Pools.Allocated, which is the agent's
// own output and still lists X because it is in use.
func TestMultiPoolManagerENIFallbackDoesNotRegain(t *testing.T) {
	h := newENIHarness(t)

	const (
		p1 = "10.0.0.0/28"
		x  = "10.0.0.16/28"
	)

	// P1 is filled and 1 pod lands on X.
	h.operatorWrites(p1, x)
	h.mustAllocate(17)
	h.sync()

	// The operator drops X from Status.ENI: X is removed but still published.
	h.operatorWrites(p1)
	h.sync()
	require.True(t, h.removed(x), "precondition: %s removed; %s", x, h.state())
	require.Contains(t, h.publishedCIDRs(), netip.MustParsePrefix(x), "precondition: %s published; %s", x, h.state())

	// An event with an empty Status.ENI carries only the agent's own echo.
	h.agentEchoWrites()
	require.True(t, h.removed(x), "%s must stay removed on the agent's own echo; %s", x, h.state())
	addr, err := h.allocateNext()
	require.ErrorIs(t, err, errAllCIDRsExhausted, "allocated %s; %s", addr, h.state())
}

// TestMultiPoolManagerENIKeepsRemovedPrefixReassignedToAnotherNode checks the
// case where the operator unassigned an in-use prefix X and EC2 re-assigned X
// to another node: X never comes back in this node's Status.ENI. The agent
// must not allocate from X again, keep the IPs that are in use (and keep
// publishing X so that the operator sees them), and drop X once they are
// released.
func TestMultiPoolManagerENIKeepsRemovedPrefixReassignedToAnotherNode(t *testing.T) {
	h := newENIHarness(t)

	const (
		p1 = "10.0.0.0/28"
		x  = "10.0.0.16/28"
		p2 = "10.0.0.32/28"
	)

	h.operatorWrites(p1, x)
	addrs := h.mustAllocate(20)
	onX := addrs[16:]
	h.sync()

	// X is gone (now on another node), and the operator attaches P2.
	h.operatorWrites(p1, p2)
	h.sync()
	require.True(t, h.removed(x), "precondition: %s removed; %s", x, h.state())
	require.Contains(t, h.publishedCIDRs(), netip.MustParsePrefix(x), "in-use %s must stay published; %s", x, h.state())

	for _, addr := range h.mustAllocate(16) {
		require.True(t, netip.MustParsePrefix(p2).Contains(addr), "allocated %s, want an IP from %s; %s", addr, p2, h.state())
	}
	h.mgr.poolsMutex.Lock()
	require.Equal(t, 36, h.pool().inUseIPCount(), "the IPs in use on %s are kept", x)
	h.mgr.poolsMutex.Unlock()

	// The pods on X go away: X is no longer published, and its mark is gone.
	h.release(onX...)
	h.operatorWrites(p1, p2)
	h.sync()
	require.NotContains(t, h.publishedCIDRs(), netip.MustParsePrefix(x), h.state())
	h.operatorWrites(p1, p2)
	require.False(t, h.removed(x), h.state())
}

// TestMultiPoolManagerENIStaleListingWithoutTombstone documents the residual
// risk of regaining removed prefixes in ENI mode (cilium/cilium#47910): the
// agent trusts Status.ENI. An operator without the released-prefix
// tombstone (older than this change, or a new leader within the tombstone
// TTL) can re-advertise a prefix X that it has just unassigned, because the
// subnet-wide EC2 listing is eventually consistent. The agent cannot tell, so
// it allocates from X until the listing is consistent again. It then stops
// allocating from X and drops X once its pods are gone.
func TestMultiPoolManagerENIStaleListingWithoutTombstone(t *testing.T) {
	const (
		p1 = "10.0.0.0/28"
		x  = "10.0.0.16/28"
		p2 = "10.0.0.32/28"
	)

	t.Run("in-use prefix is regained", func(t *testing.T) {
		h := newENIHarness(t)
		h.operatorWrites(p1, x)
		addrs := h.mustAllocate(17)
		h.sync()

		// The release race: the operator unassigned X although a pod uses
		// it, then a stale listing re-advertises X.
		h.operatorWrites(p1, p2)
		require.True(t, h.removed(x), "precondition: %s removed; %s", x, h.state())
		h.operatorWrites(p1, x, p2)
		require.False(t, h.removed(x), "stale listing: %s is regained; %s", x, h.state())
		addr, err := h.allocateNext()
		require.NoError(t, err)
		require.True(t, netip.MustParsePrefix(x).Contains(addr),
			"documented: the agent allocates %s from the unattached %s", addr, x)

		// The listing is consistent again.
		h.operatorWrites(p1, p2)
		require.True(t, h.removed(x), h.state())
		for _, addr := range h.mustAllocate(16) {
			require.False(t, netip.MustParsePrefix(x).Contains(addr), "allocated %s from %s; %s", addr, x, h.state())
		}
		h.release(addr, addrs[16])
		h.sync()
		require.NotContains(t, h.publishedCIDRs(), netip.MustParsePrefix(x), h.state())
	})

	t.Run("released prefix is reclaimed", func(t *testing.T) {
		// This is not new: a released prefix that is still listed has been
		// reclaimable since cilium/cilium#46674.
		h := newENIHarness(t)
		h.operatorWrites(p1, x)
		h.mustAllocate(8)
		h.sync()
		require.NotContains(t, h.publishedCIDRs(), netip.MustParsePrefix(x), "precondition: %s released; %s", x, h.state())

		// The operator unassigned X, but a stale listing still has it.
		h.operatorWrites(p1, x)
		h.mustAllocate(8)
		addr, err := h.allocateEventually(3)
		require.NoError(t, err)
		require.True(t, netip.MustParsePrefix(x).Contains(addr),
			"documented: the agent reclaims the unattached %s; %s", x, h.state())
	})
}

// eniOperator models the multi-pool release path of the ENI operator
// (operator/pkg/ipam/nodemanager handleMultiPoolCIDRRelease) on top of the
// EC2 mock, so that agent and operator steps can be interleaved in a fixed
// order. The excess-ip-release-delay is assumed to have elapsed whenever
// release is called. The real operator runs these steps from asynchronous
// triggers, which is why it is not used here.
type eniOperator struct {
	t      *testing.T
	cloud  *apiMock.API
	eniID  string
	marked sets.Set[netip.Prefix]
	prev   sets.Set[netip.Prefix]
}

func newENIOperator(t *testing.T, prefixes int32) *eniOperator {
	t.Helper()
	subnet := &types.Subnet{ID: "subnet-1", VirtualNetworkID: "vpc-1", AvailableAddresses: 1024}
	cloud := apiMock.NewAPI([]*types.Subnet{subnet}, nil, nil, nil)
	eniID, _, err := cloud.CreateNetworkInterface(t.Context(), 0, subnet.ID, "pods", nil, true, false)
	require.NoError(t, err)
	_, err = cloud.AttachNetworkInterface(t.Context(), 1, "i-1", eniID)
	require.NoError(t, err)
	if prefixes > 1 {
		_, err = cloud.AssignENIPrefixes(t.Context(), eniID, prefixes-1)
		require.NoError(t, err)
	}
	return &eniOperator{t: t, cloud: cloud, eniID: eniID, marked: sets.New[netip.Prefix]()}
}

// attached returns the prefixes attached to the ENI in EC2.
func (o *eniOperator) attached() []netip.Prefix {
	o.t.Helper()
	instance, err := o.cloud.GetInstance(o.t.Context(), nil, nil, "i-1")
	require.NoError(o.t, err)
	var out []netip.Prefix
	for _, p := range instance.Interfaces[o.eniID].(*awsTypes.ENI).Prefixes {
		out = append(out, p.Prefix)
	}
	return out
}

// writeStatus writes Status.ENI from EC2 to the agent.
func (o *eniOperator) writeStatus(h *eniHarness) {
	o.t.Helper()
	instance, err := o.cloud.GetInstance(o.t.Context(), nil, nil, "i-1")
	require.NoError(o.t, err)
	eni := instance.Interfaces[o.eniID].(*awsTypes.ENI)
	h.operatorWritesENIs(map[string]awsTypes.ENI{o.eniID: *eni})
}

// observe is trackMultiPoolAllocatedLocked: the CIDRs that the agent stopped
// listing in Allocated are marked for release, and re-listed ones unmarked.
// The first call marks the attached prefixes the agent does not list.
func (o *eniOperator) observe(h *eniHarness) {
	current := sets.New(h.publishedCIDRs()...)
	if o.prev == nil {
		o.prev = sets.New(o.attached()...)
	}
	o.marked.Insert(o.prev.Difference(current).UnsortedList()...)
	o.marked = o.marked.Difference(current)
	o.prev = current
}

// release GETs the CiliumNode, unmarks what the agent lists there, and
// unassigns the remaining marked prefixes in EC2.
func (o *eniOperator) release(h *eniHarness) []netip.Prefix {
	o.t.Helper()
	for _, alloc := range h.apiserver.Allocated {
		for _, c := range alloc.CIDRs {
			o.marked.Delete(c.Prefix)
		}
	}
	released := slices.SortedFunc(maps.Keys(o.marked), netip.Prefix.Compare)
	if len(released) == 0 {
		return nil
	}
	strs := make([]string, 0, len(released))
	for _, p := range released {
		strs = append(strs, p.String())
	}
	require.NoError(o.t, o.cloud.UnassignENIPrefixes(o.t.Context(), o.eniID, strs))
	o.marked = sets.New[netip.Prefix]()
	return released
}

// TestMultiPoolManagerENIReleaseRaceWithEC2 interleaves the agent with the
// operator's release path against the EC2 mock (cilium/cilium#47910). The
// agent releases an idle prefix X, then demand rises and it reclaims X and
// allocates from it before its write reaches the apiserver. The operator's
// GET before UnassignPrivateIpAddresses only protects X once the write has
// landed.
func TestMultiPoolManagerENIReleaseRaceWithEC2(t *testing.T) {
	// setup returns X, released by the agent and marked by the operator,
	// and a pod IP on X allocated after the agent reclaimed X.
	setup := func(t *testing.T) (*eniHarness, *eniOperator, netip.Prefix, netip.Addr) {
		h := newENIHarness(t)
		op := newENIOperator(t, 2)
		attached := op.attached()
		require.Len(t, attached, 2)
		x := attached[1]

		op.writeStatus(h)
		h.mustAllocate(8)
		h.sync()
		h.land()
		op.observe(h)
		require.True(t, op.marked.Has(x), "precondition: %s released by the agent and marked; %s", x, h.state())

		// Demand rises: the agent reclaims X in memory and publishes it,
		// but the write has not reached the apiserver yet.
		h.mustAllocate(8)
		addr, err := h.allocateEventually(3)
		require.NoError(t, err, h.state())
		require.True(t, x.Contains(addr), "precondition: pod got %s from reclaimed %s", addr, x)
		require.Contains(t, h.publishedCIDRs(), x)
		return h, op, x, addr
	}

	t.Run("GET after the agent's write landed keeps the prefix", func(t *testing.T) {
		h, op, x, _ := setup(t)
		h.land()
		require.Empty(t, op.release(h))
		require.Contains(t, op.attached(), x)
	})

	t.Run("GET before the agent's write landed releases an in-use prefix", func(t *testing.T) {
		h, op, x, addr := setup(t)

		// Remaining window: the GET still sees the old Allocated.
		require.Equal(t, []netip.Prefix{x}, op.release(h))
		require.NotContains(t, op.attached(), x, "residual race: %s with pod IP %s is unassigned in EC2", x, addr)

		// The agent does not wedge: X is kept as removed (its pod IP stays
		// allocated), and new pods get IPs from a newly attached prefix.
		op.writeStatus(h)
		h.sync()
		require.True(t, h.removed(x.String()), h.state())
		require.Contains(t, h.publishedCIDRs(), x, "in-use %s must stay published; %s", x, h.state())

		assigned, err := op.cloud.AssignENIPrefixes(t.Context(), op.eniID, 1)
		require.NoError(t, err)
		require.Len(t, assigned, 1)
		op.writeStatus(h)
		newAddr, err := h.allocateEventually(3)
		require.NoError(t, err, h.state())
		if fresh := netip.MustParsePrefix(assigned[0]); fresh == x {
			// EC2 handed X back to the same ENI: it is regained.
			require.False(t, h.removed(x.String()), h.state())
		} else {
			require.True(t, fresh.Contains(newAddr), "allocated %s, want an IP from %s; %s", newAddr, fresh, h.state())
		}
		require.NotEqual(t, addr, newAddr)
	})
}

// handshakeCNClient records the agent's CiliumNode writes for the release
// handshake tests. The agent's status writes are in flight until
// eniHarness.land.
type handshakeCNClient struct {
	cilium_v2.CiliumNodeInterface
	h *eniHarness
	// pruneHandshakeField drops Spec.IPAM.CIDRReleaseHandshake from spec
	// writes, like an apiserver with the CRD of an older operator.
	pruneHandshakeField bool
	specWrites          int
	statusWrites        int
}

func (c *handshakeCNClient) Update(_ context.Context, node *ciliumv2.CiliumNode, _ metav1.UpdateOptions) (*ciliumv2.CiliumNode, error) {
	c.specWrites++
	out := node.DeepCopy()
	if c.pruneHandshakeField {
		out.Spec.IPAM.CIDRReleaseHandshake = false
	}
	return out, nil
}

func (c *handshakeCNClient) UpdateStatus(_ context.Context, node *ciliumv2.CiliumNode, _ metav1.UpdateOptions) (*ciliumv2.CiliumNode, error) {
	c.statusWrites++
	c.h.inflight = &inflightStatus{
		version:      node.ResourceVersion,
		releaseCIDRs: node.Status.IPAM.ReleaseCIDRs.DeepCopy(),
	}
	return node.DeepCopy(), nil
}

// inflightStatus is a status write of the agent that has not reached the
// apiserver yet.
type inflightStatus struct {
	version      string
	releaseCIDRs types.CIDRReleaseStatusMap
}

// newENIHandshakeHarness returns an eniHarness whose agent takes part in the
// CIDR release handshake, as the ENI agent does.
func newENIHandshakeHarness(t *testing.T) (*eniHarness, *handshakeCNClient) {
	h := newENIHarness(t)
	h.mgr.poolsAccessor.CIDRReleaseHandshake = true
	client := &handshakeCNClient{h: h}
	h.mgr.cnClient = client
	h.server = types.CIDRReleaseStatusMap{}
	return h, client
}

// operatorWritesRelease simulates the operator writing status, where
// Status.IPAM.ReleaseCIDRs is set to release, and delivers it to the agent.
func (h *eniHarness) operatorWritesRelease(release types.CIDRReleaseStatusMap) {
	h.t.Helper()
	h.server = release
	h.version++
	h.operatorWritesENIs(h.enis)
}

// releaseState returns the release handshake state of x in the apiserver.
func (h *eniHarness) releaseState(x netip.Prefix) types.IPReleaseStatus {
	return h.server[iputil.PrefixFrom(x)]
}

// operatorMarks is the operator's marking pass of the handshake: the
// release candidates that are not marked yet are marked.
func (o *eniOperator) operatorMarks(h *eniHarness) {
	release := h.server.DeepCopy()
	if release == nil {
		release = types.CIDRReleaseStatusMap{}
	}
	changed := false
	for x := range o.marked {
		if _, ok := release[iputil.PrefixFrom(x)]; !ok {
			release[iputil.PrefixFrom(x)] = ipamOption.IPAMMarkForRelease
			changed = true
		}
	}
	if changed {
		h.operatorWritesRelease(release)
	}
}

// releaseAcknowledged is the operator's release pass with the handshake: it
// GETs the CiliumNode, unmarks what the agent lists in Allocated or refused,
// and unassigns in EC2 only what the agent acknowledged with
// ready-for-release. It returns the unassigned prefixes.
func (o *eniOperator) releaseAcknowledged(h *eniHarness) []netip.Prefix {
	o.t.Helper()
	listed := sets.New[netip.Prefix]()
	for _, alloc := range h.apiserver.Allocated {
		for _, c := range alloc.CIDRs {
			listed.Insert(c.Prefix)
		}
	}
	release := h.server.DeepCopy()
	var released []netip.Prefix
	for _, x := range slices.SortedFunc(maps.Keys(o.marked), netip.Prefix.Compare) {
		key := iputil.PrefixFrom(x)
		switch {
		case listed.Has(x), release[key] == ipamOption.IPAMDoNotRelease:
			o.marked.Delete(x)
			delete(release, key)
		case release[key] == ipamOption.IPAMReadyForRelease:
			require.NoError(o.t, o.cloud.UnassignENIPrefixes(o.t.Context(), o.eniID, []string{x.String()}))
			o.marked.Delete(x)
			release[key] = ipamOption.IPAMReleased
			released = append(released, x)
		}
	}
	if !release.DeepEqual(&h.server) || len(released) > 0 {
		o.writeStatusWithRelease(h, release)
	}
	return released
}

// writeStatusWithRelease writes Status.ENI from EC2 together with release.
func (o *eniOperator) writeStatusWithRelease(h *eniHarness, release types.CIDRReleaseStatusMap) {
	o.t.Helper()
	instance, err := o.cloud.GetInstance(o.t.Context(), nil, nil, "i-1")
	require.NoError(o.t, err)
	eni := instance.Interfaces[o.eniID].(*awsTypes.ENI)
	h.enis = map[string]awsTypes.ENI{o.eniID: *eni}
	h.operatorWritesRelease(release)
}

// TestMultiPoolManagerENIReleaseHandshakeTransitions walks the agent through
// the transitions of the CIDR release handshake with the ENI accessor
// (cilium/cilium#47910).
func TestMultiPoolManagerENIReleaseHandshakeTransitions(t *testing.T) {
	setup := func(t *testing.T) (*eniHarness, *handshakeCNClient, *eniOperator, netip.Prefix) {
		h, client := newENIHandshakeHarness(t)
		op := newENIOperator(t, 2)
		x := op.attached()[1]
		op.writeStatus(h)
		h.mustAllocate(8)
		h.sync()
		h.land()
		op.observe(h)
		require.True(t, op.marked.Has(x), "precondition: %s released and a release candidate; %s", x, h.state())
		return h, client, op, x
	}

	t.Run("agent advertises the handshake once", func(t *testing.T) {
		h, client, _, _ := setup(t)
		require.Equal(t, 1, client.specWrites)
		for range 3 {
			h.sync()
		}
		require.Equal(t, 1, client.specWrites)
	})

	t.Run("advertisement pruned by an old CRD is not rewritten on every sync", func(t *testing.T) {
		h, client := newENIHandshakeHarness(t)
		client.pruneHandshakeField = true
		h.operatorWrites("10.0.0.0/28")
		for range 3 {
			h.sync()
		}
		require.Equal(t, 1, client.specWrites)
	})

	t.Run("marked-for-release to ready-for-release to released", func(t *testing.T) {
		h, client, op, x := setup(t)
		op.operatorMarks(h)
		require.Equal(t, types.IPReleaseStatus(ipamOption.IPAMMarkForRelease), h.releaseState(x))
		h.sync()
		h.land()
		require.Equal(t, types.IPReleaseStatus(ipamOption.IPAMReadyForRelease), h.releaseState(x))
		require.NotContains(t, h.publishedCIDRs(), x)

		require.Equal(t, []netip.Prefix{x}, op.releaseAcknowledged(h))
		require.Equal(t, types.IPReleaseStatus(ipamOption.IPAMReleased), h.releaseState(x))

		// x is no longer advertised: the agent ends the handshake.
		writes := client.statusWrites
		h.sync()
		h.land()
		require.Equal(t, writes+1, client.statusWrites)
		require.NotContains(t, h.server, iputil.PrefixFrom(x))
	})

	t.Run("in-use CIDR is answered with do-not-release", func(t *testing.T) {
		h, _, op, x := setup(t)
		// The agent reclaims x and allocates from it before the mark
		// reaches it, and its write has not landed.
		h.mustAllocate(8)
		addr, err := h.allocateEventually(3)
		require.NoError(t, err, h.state())
		require.True(t, x.Contains(addr))

		op.operatorMarks(h)
		h.sync()
		require.Empty(t, op.releaseAcknowledged(h), "nothing is unassigned before the answer landed")
		h.land()
		require.Equal(t, types.IPReleaseStatus(ipamOption.IPAMDoNotRelease), h.releaseState(x))
		require.Empty(t, op.releaseAcknowledged(h))
		require.NotContains(t, h.server, iputil.PrefixFrom(x), "do-not-release clears the mark")
		require.Contains(t, op.attached(), x)
		require.False(t, op.marked.Has(x))
	})

	t.Run("marked CIDR is not reclaimed when demand rises", func(t *testing.T) {
		h, _, op, x := setup(t)
		op.operatorMarks(h)
		h.mustAllocate(8)
		_, err := h.allocateEventually(3)
		require.ErrorIs(t, err, errAllCIDRsExhausted, h.state())
		h.land()
		require.Equal(t, []netip.Prefix{x}, op.releaseAcknowledged(h))
	})

	t.Run("cleared mark lets the agent reclaim the CIDR", func(t *testing.T) {
		h, _, op, x := setup(t)
		op.operatorMarks(h)
		h.sync()
		h.land()
		// The operator gives up, e.g. because the node needs the IPs.
		op.marked.Delete(x)
		h.operatorWritesRelease(types.CIDRReleaseStatusMap{})
		h.mustAllocate(8)
		addr, err := h.allocateEventually(3)
		require.NoError(t, err, h.state())
		require.True(t, x.Contains(addr))
	})

	t.Run("agent restart keeps an acknowledged CIDR blocked", func(t *testing.T) {
		h, _, op, x := setup(t)
		op.operatorMarks(h)
		h.sync()
		h.land()
		require.Equal(t, types.IPReleaseStatus(ipamOption.IPAMReadyForRelease), h.releaseState(x))

		restarted, _ := newENIHandshakeHarness(t)
		restarted.server = h.server
		restarted.enis = h.enis
		restarted.mgr.finishedRestore = map[Family]bool{}
		restarted.operatorWritesENIs(h.enis)
		restarted.mgr.RestoreFinished(IPv4)
		restarted.sync()
		require.NotContains(t, restarted.publishedCIDRs(), x)
		restarted.mustAllocate(16)
		_, err := restarted.allocateNext()
		require.ErrorIs(t, err, errAllCIDRsExhausted, restarted.state())
	})

	t.Run("old operator without marks behaves as before", func(t *testing.T) {
		h, _, _, x := setup(t)
		h.mustAllocate(8)
		addr, err := h.allocateEventually(3)
		require.NoError(t, err, h.state())
		require.True(t, x.Contains(addr), "the agent reclaims %s as without the handshake", x)
	})
}

// multisetPermutations calls fn with every distinct ordering of steps.
func multisetPermutations(steps []string, fn func([]string)) {
	slices.Sort(steps)
	var rec func(prefix []string, rest []string)
	rec = func(prefix []string, rest []string) {
		if len(rest) == 0 {
			fn(prefix)
			return
		}
		for i := range rest {
			if i > 0 && rest[i] == rest[i-1] {
				continue
			}
			next := slices.Concat(rest[:i], rest[i+1:])
			rec(append(slices.Clone(prefix), rest[i]), next)
		}
	}
	rec(nil, steps)
}

// TestMultiPoolManagerENIReleaseHandshakeInterleavings runs every ordering of
// the agent's and the operator's steps after the agent released prefix x
// (cilium/cilium#47910), and checks that no pod IP is ever in a prefix that
// was unassigned in EC2:
//   - alloc: 9 pods are created, which needs x once the first /28 is full;
//   - sync: the agent's sync round (answer marks, reclaim, publish);
//   - land: the agent's writes reach the apiserver;
//   - mark: the operator's marking pass;
//   - release: the operator's GET and EC2 release pass.
//
// Without the handshake the same orderings do unassign in-use prefixes,
// which shows that they cover the race.
func TestMultiPoolManagerENIReleaseHandshakeInterleavings(t *testing.T) {
	steps := []string{"alloc", "alloc", "sync", "sync", "land", "mark", "release"}
	// Let the handshake run to completion after each ordering.
	tail := []string{"sync", "land", "release", "sync", "land", "release"}

	run := func(t *testing.T, handshake bool, order []string) (violation string, unassigned bool) {
		var h *eniHarness
		if handshake {
			h, _ = newENIHandshakeHarness(t)
		} else {
			h = newENIHarness(t)
		}
		op := newENIOperator(t, 2)
		x := op.attached()[1]
		op.writeStatus(h)
		pods := h.mustAllocate(8)
		h.sync()
		h.land()
		op.observe(h)
		require.True(t, op.marked.Has(x))

		for i, step := range slices.Concat(order, tail) {
			switch step {
			case "alloc":
				for range 9 {
					addr, err := h.allocateNext()
					if err != nil {
						break
					}
					pods = append(pods, addr)
				}
			case "sync":
				h.sync()
			case "land":
				h.land()
			case "mark":
				if handshake {
					op.operatorMarks(h)
				}
			case "release":
				var released []netip.Prefix
				if handshake {
					released = op.releaseAcknowledged(h)
				} else {
					released = op.release(h)
				}
				unassigned = unassigned || slices.Contains(released, x)
			}
			attached := op.attached()
			for _, addr := range pods {
				if !slices.ContainsFunc(attached, func(p netip.Prefix) bool { return p.Contains(addr) }) {
					return fmt.Sprintf("after step %d (%s) of %v: pod IP %s unassigned", i, step, order, addr), unassigned
				}
			}
		}
		return "", unassigned
	}

	t.Run("with the handshake no in-use prefix is unassigned", func(t *testing.T) {
		orders, unassigned := 0, 0
		multisetPermutations(slices.Clone(steps), func(order []string) {
			orders++
			violation, released := run(t, true, order)
			require.Empty(t, violation)
			if released {
				unassigned++
			}
		})
		require.Equal(t, 1260, orders)
		// Liveness: idle prefixes are still released.
		require.NotZero(t, unassigned)
	})

	t.Run("without the handshake some orderings unassign an in-use prefix", func(t *testing.T) {
		violations := 0
		multisetPermutations(slices.Clone(steps), func(order []string) {
			if violation, _ := run(t, false, order); violation != "" {
				violations++
			}
		})
		require.NotZero(t, violations)
	})
}
