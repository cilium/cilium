// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
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
	"go4.org/netipx"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/hive"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/podippool"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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
		assert.Equal(t, map[Pool]map[string]string{
			PoolDefault(): {
				defaultAllocation.IP.String(): "",
			},
			Pool("mars"): {
				marsAllocation.IP.String(): "",
			},
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

// toCIDR converts a netip.Prefix into a *cidr.CIDR for assertions that compare
// against LocalNode.{IPv4,IPv6}AllocCIDR / {IPv4,IPv6}SecondaryAllocCIDRs.
// The prefix is masked to match net.ParseCIDR semantics used to populate
// those fields.
func toCIDR(p netip.Prefix) *cidr.CIDR {
	return cidr.NewCIDR(netipx.PrefixIPNet(p.Masked()))
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
			toCIDR(defaultIPv4CIDR1), localNode.IPv4AllocCIDR,
			"IPv4 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv4SecondaryAllocCIDRs, []*cidr.CIDR{toCIDR(marsIPv4CIDR1)},
			"IPv4 secondary allocation CIDRs do not match",
		)
		assert.Equalf(c,
			toCIDR(defaultIPv6CIDR1), localNode.IPv6AllocCIDR,
			"IPv6 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv6SecondaryAllocCIDRs, []*cidr.CIDR{toCIDR(marsIPv6CIDR1)},
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
			toCIDR(defaultIPv4CIDR1), localNode.IPv4AllocCIDR,
			"IPv4 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv4SecondaryAllocCIDRs, []*cidr.CIDR{toCIDR(marsIPv4CIDR1), toCIDR(jupiterIPv4CIDR)},
			"IPv4 secondary allocation CIDRs do not match",
		)
		assert.Equalf(c,
			toCIDR(defaultIPv6CIDR1), localNode.IPv6AllocCIDR,
			"IPv6 primary allocation CIDR do not match",
		)
		assert.ElementsMatch(c,
			localNode.IPv6SecondaryAllocCIDRs, []*cidr.CIDR{toCIDR(marsIPv6CIDR1), toCIDR(jupiterIPv6CIDR)},
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
			toCIDR(defaultIPv4CIDR1), localNode.IPv4AllocCIDR,
			"IPv4 primary allocation CIDR do not match",
		)
		assert.Empty(c,
			localNode.IPv4SecondaryAllocCIDRs,
			"IPv4 secondary allocation CIDRs do not match",
		)
		assert.Equalf(c,
			toCIDR(defaultIPv6CIDR1), localNode.IPv6AllocCIDR,
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
						"10.0.0.1": types.AllocationIP{Resource: "pod-a"},
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

	mgr.upsertPoolLocked("default", []iputil.Prefix{prefix}, false, false)
	_, err := mgr.AllocateIP(lastIP, "pod-a", "default", IPv4, false)
	require.Error(t, err)

	mgr.upsertPoolLocked("default", []iputil.Prefix{prefix}, false, true)
	result, err := mgr.AllocateIP(lastIP, "pod-a", "default", IPv4, false)
	require.NoError(t, err)
	require.Equal(t, lastIP, result.IP)
}

func Test_multiPoolManager_staticIPStatus(t *testing.T) {
	newNode := func(tags map[string]string, assigned string) *ciliumv2.CiliumNode {
		return &ciliumv2.CiliumNode{
			Spec: ciliumv2.NodeSpec{
				IPAM: types.IPAMSpec{StaticIPTags: tags},
			},
			Status: ciliumv2.NodeStatus{
				IPAM: types.IPAMStatus{AssignedStaticIP: assigned},
			},
		}
	}

	tests := []struct {
		name                  string
		node                  *ciliumv2.CiliumNode
		wantRequestedStaticIP bool
		wantAssignedStaticIP  string
	}{
		{
			name:                  "nil node",
			node:                  nil,
			wantRequestedStaticIP: false,
			wantAssignedStaticIP:  "",
		},
		{
			name:                  "no static IP requested",
			node:                  newNode(nil, ""),
			wantRequestedStaticIP: false,
			wantAssignedStaticIP:  "",
		},
		{
			name:                  "static IP requested but not yet assigned",
			node:                  newNode(map[string]string{"env": "prod"}, ""),
			wantRequestedStaticIP: true,
			wantAssignedStaticIP:  "",
		},
		{
			name:                  "static IP requested and assigned",
			node:                  newNode(map[string]string{"env": "prod"}, "1.2.3.4"),
			wantRequestedStaticIP: true,
			wantAssignedStaticIP:  "1.2.3.4",
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
		CiliumPodIPPool: &k8sv2alpha1.CiliumPodIPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Annotations: ann,
			},
			Spec: k8sv2alpha1.IPPoolSpec{
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

	v4Alloc, _ := newMultiPoolAllocators(MultiPoolAllocatorParams{
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

	return v4Alloc
}
