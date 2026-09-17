// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"math/big"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func request(pool string, ipv4Addrs, ipv6Addrs int) ipamTypes.IPAMPoolRequest {
	return ipamTypes.IPAMPoolRequest{
		Pool: pool,
		Needed: ipamTypes.IPAMPoolDemand{
			IPv4Addrs: ipv4Addrs,
			IPv6Addrs: ipv6Addrs,
		},
	}
}

func allocation(pool string, cidrs ...string) ipamTypes.IPAMPoolAllocation {
	allocation := ipamTypes.IPAMPoolAllocation{Pool: pool}
	for _, cidr := range cidrs {
		allocation.CIDRs = append(allocation.CIDRs, iputil.PrefixFrom(netip.MustParsePrefix(cidr)))
	}
	return allocation
}

func testNode(name string, requested []ipamTypes.IPAMPoolRequest, allocated []ipamTypes.IPAMPoolAllocation) *v2.CiliumNode {
	return &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Requested: requested,
					Allocated: allocated,
				},
			},
		},
	}
}

func TestPoolAllocator(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t), true, true)
	err := p.UpsertPool("default",
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("10.100.0.0/16")},
			{cidr: netip.MustParsePrefix("10.200.0.0/16")},
		}, 24,
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("fd00:100::/80")},
			{cidr: netip.MustParsePrefix("fc00:100::/80")},
		}, 96,
	)
	require.NoError(t, err)
	defaultPool, exists := p.pools["default"]
	require.True(t, exists)
	require.Equal(t, 24, defaultPool.v4MaskSize)
	require.Equal(t, 96, defaultPool.v6MaskSize)

	// node1 is a node which has some previously allocated CIDRs
	node1 := testNode("node1",
		[]ipamTypes.IPAMPoolRequest{request("default", 10, 10)},
		[]ipamTypes.IPAMPoolAllocation{allocation("default",
			"10.100.10.0/24",
			"10.100.20.0/24",
			"fd00:100:0:0:0:10::/96",
		)},
	)

	// node2 is a new node which needs a fresh allocation
	node2 := testNode("node2",
		[]ipamTypes.IPAMPoolRequest{request("default", 10, 10)},
		nil,
	)

	// node3 is a new node which is attempting to steal a CIDR from node1
	node3 := testNode("node3",
		nil,
		[]ipamTypes.IPAMPoolAllocation{allocation("default", "10.100.10.0/24")}, // already allocated to node1
	)

	// node1 has some pre-allocated pools that need to be restored
	err = p.AllocateToNode(node1.Name, node1.Spec.IPAM.Pools)
	require.ErrorIs(t, ErrAllocatorNotReady, err)
	// allocation shouldn't change since the allocator is not ready yet
	require.Equal(t, node1.Spec.IPAM.Pools.Allocated, p.AllocatedPools(node1.Name))

	// node2 must not allocate before restoration has finished
	err = p.AllocateToNode(node2.Name, node2.Spec.IPAM.Pools)
	require.ErrorIs(t, ErrAllocatorNotReady, err)
	require.Empty(t, p.AllocatedPools(node2.Name))

	// node3 must not steal the restored CIDR from node1
	err = p.AllocateToNode(node3.Name, node3.Spec.IPAM.Pools)
	require.ErrorIs(t, ErrAllocatorNotReady, err)
	require.Empty(t, p.AllocatedPools(node3.Name))

	// Mark as ready
	p.RestoreFinished()

	// The following is a no-op, but should not return any errors
	err = p.AllocateToNode(node1.Name, node1.Spec.IPAM.Pools)
	require.NoError(t, err)
	require.Equal(t, node1.Spec.IPAM.Pools.Allocated, p.AllocatedPools(node1.Name))

	// The following should allocate one IPv4 and IPv6 CIDR each to node2
	err = p.AllocateToNode(node2.Name, node2.Spec.IPAM.Pools)
	require.NoError(t, err)
	node2.Spec.IPAM.Pools.Allocated = p.AllocatedPools(node2.Name)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("default", "10.100.0.0/24", "fd00:100::/96"),
	}, node2.Spec.IPAM.Pools.Allocated)

	// The following should be rejected, because the CIDR is owned by node1
	err = p.AllocateToNode(node3.Name, node3.Spec.IPAM.Pools)
	require.EqualError(t, err, "unable to reuse from pool default: cidr 10.100.10.0/24 has already been allocated")
	require.Empty(t, p.AllocatedPools(node3.Name))

	// Release 10.100.10.0/24 from node1
	node1.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
		allocation("default", "10.100.20.0/24", "fd00:100::10:0:0/96"),
	}
	err = p.AllocateToNode(node1.Name, node1.Spec.IPAM.Pools)
	require.NoError(t, err)
	require.Equal(t, node1.Spec.IPAM.Pools.Allocated, p.AllocatedPools(node1.Name))

	// node3 can now allocate 10.100.10.0/24
	err = p.AllocateToNode(node3.Name, node3.Spec.IPAM.Pools)
	require.NoError(t, err)
	node3.Spec.IPAM.Pools.Allocated = p.AllocatedPools(node3.Name)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("default", "10.100.10.0/24"),
	}, node3.Spec.IPAM.Pools.Allocated)

	// Release node2
	err = p.ReleaseNode(node2.Name)
	require.NoError(t, err)
	require.Empty(t, p.AllocatedPools(node2.Name))

	// Try to allocate released CIDR from node2 to node3
	node3.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
		allocation("default", "10.100.0.0/24", "10.100.10.0/24"),
	}
	err = p.AllocateToNode(node3.Name, node3.Spec.IPAM.Pools)
	require.NoError(t, err)
	require.Equal(t, node3.Spec.IPAM.Pools.Allocated, p.AllocatedPools(node3.Name))

	// Increase demand for node1, this should allocate a new CIDR
	node1.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
		request("default", 300, 10),
	}
	err = p.AllocateToNode(node1.Name, node1.Spec.IPAM.Pools)
	require.NoError(t, err)
	node1.Spec.IPAM.Pools.Allocated = p.AllocatedPools(node1.Name)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("default", "10.100.1.0/24", "10.100.20.0/24", "fd00:100::10:0:0/96"),
	}, node1.Spec.IPAM.Pools.Allocated)
}

func TestPoolAllocator_PoolErrors(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t), true, true)
	p.RestoreFinished()

	node := testNode("node1",
		[]ipamTypes.IPAMPoolRequest{request("no-exist", 10, 0)},
		nil,
	)

	err := p.AllocateToNode(node.Name, node.Spec.IPAM.Pools)
	require.ErrorContains(t, err, `failed to allocate ipv4 address for node "node1" from pool "no-exist"`)
	require.ErrorContains(t, err, `cannot allocate from non-existing pool: no-exist`)

	err = p.UpsertPool("ipv4-only",
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("10.0.0.0/16")}}, 24,
		nil, 0,
	)
	require.NoError(t, err)
	node.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
		// we require IPv6 addresses from an IPv4-only pool
		request("ipv4-only", 0, 10),
	}
	err = p.AllocateToNode(node.Name, node.Spec.IPAM.Pools)
	require.ErrorContains(t, err, `failed to allocate ipv6 address for node "node1" from pool "ipv4-only"`)
	require.ErrorContains(t, err, `pool empty`)

	err = p.UpsertPool("ipv4-only-same-cidr",
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("10.0.0.0/16")}}, 24,
		nil, 0,
	)
	require.NoError(t, err)
	err = p.UpsertPool("ipv6-only",
		nil, 0,
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("fd00:100::/80")}}, 96,
	)
	require.NoError(t, err)
	node.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
		request("ipv4-only", 10, 10),
		request("ipv4-only-same-cidr", 10, 10),
		request("ipv6-only", 10, 10),
	}
	err = p.AllocateToNode(node.Name, node.Spec.IPAM.Pools)
	require.ErrorContains(t, err, `failed to allocate ipv6 address for node "node1" from pool "ipv4-only"`)
	require.ErrorContains(t, err, `failed to allocate ipv6 address for node "node1" from pool "ipv4-only-same-cidr"`)
	require.ErrorContains(t, err, `failed to allocate ipv4 address for node "node1" from pool "ipv6-only"`)
	require.ErrorContains(t, err, `pool empty`)
	// Some allocations will have failed, but we still expect everything else to have succeeded
	node.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
		allocation("ipv4-only", "10.0.0.0/24"),
		allocation("ipv4-only-same-cidr", "10.0.0.0/24"),
		allocation("ipv6-only", "fd00:100::/96"),
	}
	require.Equal(t, node.Spec.IPAM.Pools.Allocated, p.AllocatedPools(node.Name))

	// Try to occupy invalid CIDR
	node.Spec.IPAM.Pools.Allocated[0] = ipamTypes.IPAMPoolAllocation{
		Pool: "ipv4-only",
		CIDRs: []iputil.Prefix{
			iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			{}, // zero-value Prefix: invalid
		},
	}
	err = p.AllocateToNode(node.Name, node.Spec.IPAM.Pools)
	require.ErrorContains(t, err, `invalid CIDR`)
}

func TestPoolAllocator_AddUpsertDelete(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t), true, true)

	// Upserting a non-existing pool adds it
	_, exists := p.pools["mars"]
	require.False(t, exists)
	err := p.UpsertPool("mars",
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("10.10.0.0/16")},
			{cidr: netip.MustParsePrefix("10.20.0.0/16")},
		}, 24,
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("fe00:100::/80")},
			{cidr: netip.MustParsePrefix("fb00:200::/80")},
		}, 96,
	)
	require.NoError(t, err)
	mars, exists := p.pools["mars"]
	require.True(t, exists)
	require.Equal(t, 24, mars.v4MaskSize)
	require.Equal(t, 96, mars.v6MaskSize)
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("10.10.0.0/16")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("10.20.0.0/16")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("fb00:200::/80")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("fe00:100::/80")))

	// IPv4 mask size cannot be changed on existing pool
	err = p.UpsertPool("mars",
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("10.10.0.0/16")},
			{cidr: netip.MustParsePrefix("10.30.0.0/16")},
		}, 25,
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("fa00:100::/80")},
			{cidr: netip.MustParsePrefix("fb00:200::/80")},
		}, 97,
	)
	require.ErrorContains(t, err, `"mars": cannot change IPv4 mask size`)
	mars, exists = p.pools["mars"]
	require.True(t, exists)
	require.Equal(t, 24, mars.v4MaskSize)
	require.Equal(t, 96, mars.v6MaskSize)
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("10.10.0.0/16")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("10.20.0.0/16")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("fe00:100::/80")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("fb00:200::/80")))

	// IPv6 mask size cannot be changed on existing pool
	err = p.UpsertPool("mars",
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("10.1.0.0/16")},
			{cidr: netip.MustParsePrefix("10.3.0.0/16")},
		}, 24,
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("fa00:100::/80")},
			{cidr: netip.MustParsePrefix("fb00:200::/80")},
		}, 97,
	)
	require.ErrorContains(t, err, `"mars": cannot change IPv6 mask size`)
	mars, exists = p.pools["mars"]
	require.True(t, exists)
	require.Equal(t, 24, mars.v4MaskSize)
	require.Equal(t, 96, mars.v6MaskSize)
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("10.10.0.0/16")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("10.20.0.0/16")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("fe00:100::/80")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("fb00:200::/80")))

	// allowFirstIP cannot be changed on existing pool
	err = p.UpsertPool("mars",
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("10.10.0.0/16")},
			{cidr: netip.MustParsePrefix("10.20.0.0/16")},
		}, 24,
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("fe00:100::/80")},
			{cidr: netip.MustParsePrefix("fb00:200::/80")},
		}, 96,
		WithAllowFirstIP(),
	)
	require.ErrorContains(t, err, `"mars": cannot change allowFirstIP`)
	mars, exists = p.pools["mars"]
	require.True(t, exists)
	require.False(t, mars.allowFirstIP)
	require.False(t, mars.allowLastIP)

	// allowLastIP cannot be changed on existing pool
	err = p.UpsertPool("mars",
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("10.10.0.0/16")},
			{cidr: netip.MustParsePrefix("10.20.0.0/16")},
		}, 24,
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("fe00:100::/80")},
			{cidr: netip.MustParsePrefix("fb00:200::/80")},
		}, 96,
		WithAllowLastIP(),
	)
	require.ErrorContains(t, err, `"mars": cannot change allowLastIP`)
	mars, exists = p.pools["mars"]
	require.True(t, exists)
	require.False(t, mars.allowFirstIP)
	require.False(t, mars.allowLastIP)

	// Changes in pool CIDRs are reflected in internal bookkeeping after upsert
	err = p.UpsertPool("mars",
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("10.1.0.0/16")},
			{cidr: netip.MustParsePrefix("10.3.0.0/16")},
			{cidr: netip.MustParsePrefix("10.10.0.0/16")},
		}, 24,
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("fa00:100::/80")},
			{cidr: netip.MustParsePrefix("fc00:200::/80")},
			{cidr: netip.MustParsePrefix("fe00:100::/80")},
		}, 96,
	)
	require.NoError(t, err)
	mars, exists = p.pools["mars"]
	require.True(t, exists)
	require.Equal(t, 24, mars.v4MaskSize)
	require.Equal(t, 96, mars.v6MaskSize)
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("10.1.0.0/16")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("10.3.0.0/16")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("10.10.0.0/16")))
	require.False(t, mars.hasCIDR(netip.MustParsePrefix("10.20.0.0/16")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("fa00:100::/80")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("fc00:200::/80")))
	require.True(t, mars.hasCIDR(netip.MustParsePrefix("fe00:100::/80")))
	require.False(t, mars.hasCIDR(netip.MustParsePrefix("fb00:200::/80")))

	// Deleting a non-existing pool fails
	err = p.DeletePool("saturn")
	require.ErrorContains(t, err, `pool "saturn" requested for deletion doesn't exist`)

	// Deleting an existing pool removes it completely
	err = p.DeletePool("mars")
	require.NoError(t, err)
	_, exists = p.pools["mars"]
	require.False(t, exists)
}

func Test_addrsInPrefix(t *testing.T) {
	mustParseBigInt := func(s string) *big.Int {
		r := new(big.Int)
		r.SetString(s, 0)
		return r
	}

	tests := []struct {
		name         string
		args         netip.Prefix
		allowFirstIP bool
		allowLastIP  bool
		want         *big.Int
	}{
		{
			name: "ipv4",
			args: netip.MustParsePrefix("10.0.0.0/24"),
			want: big.NewInt(254),
		},
		{
			name: "ipv6",
			args: netip.MustParsePrefix("f00d::/48"),
			want: mustParseBigInt("1208925819614629174706174"),
		},
		{
			name: "zero",
			args: netip.Prefix{},
			want: big.NewInt(0),
		},
		{
			name: "/32",
			args: netip.MustParsePrefix("10.0.0.0/32"),
			want: big.NewInt(1),
		},
		{
			name: "/31",
			args: netip.MustParsePrefix("10.0.0.0/31"),
			want: big.NewInt(2),
		},
		{
			name: "/30",
			args: netip.MustParsePrefix("10.0.0.0/30"),
			want: big.NewInt(2),
		},
		{
			name:         "/30 with first IP allowed",
			args:         netip.MustParsePrefix("10.0.0.0/30"),
			allowFirstIP: true,
			want:         big.NewInt(3),
		},
		{
			name:        "/30 with last IP allowed",
			args:        netip.MustParsePrefix("10.0.0.0/30"),
			allowLastIP: true,
			want:        big.NewInt(3),
		},
		{
			name:         "/30 with first and last IPs allowed",
			args:         netip.MustParsePrefix("10.0.0.0/30"),
			allowFirstIP: true,
			allowLastIP:  true,
			want:         big.NewInt(4),
		},
		{
			name:         "ipv6 with first and last IPs allowed",
			args:         netip.MustParsePrefix("f00d::/126"),
			allowFirstIP: true,
			allowLastIP:  true,
			want:         big.NewInt(4),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addrsInPrefix(tt.args, tt.allowFirstIP, tt.allowLastIP); got.Cmp(tt.want) != 0 {
				t.Errorf("addrsInPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPoolAllocatorAllowFirstAndLastIPs(t *testing.T) {
	tests := []struct {
		name              string
		options           []PoolOption
		allowFirstIP      bool
		allowLastIP       bool
		expectedAllocated []iputil.Prefix
	}{
		{
			name: "disabled",
			expectedAllocated: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/30")),
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.4/30")),
			},
		},
		{
			name:         "first IP allowed",
			options:      []PoolOption{WithAllowFirstIP()},
			allowFirstIP: true,
			expectedAllocated: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/30")),
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.4/30")),
			},
		},
		{
			name:        "last IP allowed",
			options:     []PoolOption{WithAllowLastIP()},
			allowLastIP: true,
			expectedAllocated: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/30")),
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.4/30")),
			},
		},
		{
			name:         "first and last IPs allowed",
			options:      []PoolOption{WithAllowFirstIP(), WithAllowLastIP()},
			allowFirstIP: true,
			allowLastIP:  true,
			expectedAllocated: []iputil.Prefix{
				iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/30")),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPoolAllocator(hivetest.Logger(t), true, false)
			err := p.UpsertPool("test-pool", []poolCIDRConfig{{cidr: netip.MustParsePrefix("10.0.0.0/29")}}, 30, nil, 0, tt.options...)
			require.NoError(t, err)
			p.RestoreFinished()

			node := testNode("node",
				[]ipamTypes.IPAMPoolRequest{request("test-pool", 4, 0)},
				nil,
			)

			err = p.AllocateToNode(node.Name, node.Spec.IPAM.Pools)
			require.NoError(t, err)
			require.Equal(t, []ipamTypes.IPAMPoolAllocation{
				{
					Pool:         "test-pool",
					AllowFirstIP: tt.allowFirstIP,
					AllowLastIP:  tt.allowLastIP,
					CIDRs:        tt.expectedAllocated,
				},
			}, p.AllocatedPools(node.Name))
		})
	}
}

// TestUpdateCIDRSets_ShrinkPool ensures that shrinking a pool does not
// trigger a nil dereference in updateCIDRSets.
func TestUpdateCIDRSets_ShrinkPool(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t), true, true)

	// Initial pool with two IPv4 CIDRs
	err := p.UpsertPool("shrink-test",
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("10.0.0.0/16")},
			{cidr: netip.MustParsePrefix("10.1.0.0/16")},
		}, 24,
		nil, 0,
	)
	require.NoError(t, err)

	pool := p.pools["shrink-test"]

	// Shrink pool to a single CIDR
	newCIDRs := []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}

	updated, err := p.updateCIDRSets(false, pool.v4, newCIDRs, 24)
	require.NoError(t, err)
	require.Len(t, updated, 1)
	require.True(t, updated[0].IsClusterCIDR(newCIDRs[0]))
}

func TestPoolUpdateWithCIDRInUse(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t), true, true)

	// no pools available
	require.Empty(t, p.pools)

	// node requests allocations from test-pool
	node := testNode("node",
		[]ipamTypes.IPAMPoolRequest{request("test-pool", 10, 10)},
		nil,
	)

	// Mark as ready
	p.RestoreFinished()

	// upsert new pool test-pool
	err := p.UpsertPool("test-pool",
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("10.100.0.0/16")}}, 24,
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("fd00:100::/80")}}, 96,
	)
	require.NoError(t, err)
	testPool, exists := p.pools["test-pool"]
	require.True(t, exists)
	require.Equal(t, 24, testPool.v4MaskSize)
	require.Equal(t, 96, testPool.v6MaskSize)

	// allocate to node from test-pool
	err = p.AllocateToNode(node.Name, node.Spec.IPAM.Pools)
	require.NoError(t, err)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.0.0/24", "fd00:100::/96"),
	}, p.AllocatedPools(node.Name))

	// remove v4 CIDRs from "test-pool"
	err = p.UpsertPool("test-pool",
		nil, 24,
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("fd00:100::/80")}}, 96,
	)
	require.NoError(t, err)

	// "10.100.0.0/24" should not be allocated to the node anymore
	require.Equal(t, map[string]poolToCIDRs{
		node.Name: {
			"test-pool": {
				v4: cidrSet{},
				v6: cidrSet{netip.MustParsePrefix("fd00:100::/96"): {}},
			},
		},
	}, p.nodes)
}

func TestOrphanCIDRs(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t), true, true)

	// no pools available
	require.Empty(t, p.pools)

	// node1 requests allocations from test-pool
	node1 := testNode("node1",
		[]ipamTypes.IPAMPoolRequest{request("test-pool", 10, 10)},
		nil,
	)

	// node2 requests allocations from test-pool
	node2 := testNode("node2",
		[]ipamTypes.IPAMPoolRequest{request("test-pool", 10, 10)},
		nil,
	)
	// node3 requests allocations from test-pool
	node3 := testNode("node3",
		[]ipamTypes.IPAMPoolRequest{request("test-pool", 10, 10)},
		nil,
	)

	// Mark as ready
	p.RestoreFinished()

	// no allocations yet
	require.Empty(t, p.AllocatedPools(node1.Name))
	require.Empty(t, p.AllocatedPools(node2.Name))
	require.Empty(t, p.AllocatedPools(node3.Name))

	// upsert new pool test-pool
	err := p.UpsertPool("test-pool",
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("10.100.0.0/16")}}, 24,
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("fd00:100::/80")}}, 96,
	)
	require.NoError(t, err)
	testPool, exists := p.pools["test-pool"]
	require.True(t, exists)
	require.Equal(t, 24, testPool.v4MaskSize)
	require.Equal(t, 96, testPool.v6MaskSize)

	// allocate to node1 from test-pool
	err = p.AllocateToNode(node1.Name, node1.Spec.IPAM.Pools)
	require.NoError(t, err)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.0.0/24", "fd00:100::/96"),
	}, p.AllocatedPools(node1.Name))
	require.Equal(t, poolToCIDRs{
		"test-pool": {
			v4: cidrSet{netip.MustParsePrefix("10.100.0.0/24"): struct{}{}},
			v6: cidrSet{netip.MustParsePrefix("fd00:100::/96"): struct{}{}},
		},
	}, p.nodes[node1.Name])

	// allocate to node2 from test-pool
	err = p.AllocateToNode(node2.Name, node2.Spec.IPAM.Pools)
	require.NoError(t, err)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.1.0/24", "fd00:100::1:0:0/96"),
	}, p.AllocatedPools(node2.Name))
	require.Equal(t, poolToCIDRs{
		"test-pool": {
			v4: cidrSet{netip.MustParsePrefix("10.100.1.0/24"): struct{}{}},
			v6: cidrSet{netip.MustParsePrefix("fd00:100::1:0:0/96"): struct{}{}},
		},
	}, p.nodes[node2.Name])

	// delete test-pool
	err = p.DeletePool("test-pool")
	require.NoError(t, err)

	// all previously allocated CIDRs are now orphaned, even if they are kept as allocated in the CiliumNode
	require.Empty(t, p.nodes[node1.Name])
	require.Empty(t, p.nodes[node2.Name])
	require.Equal(t, map[string]poolToCIDRs{
		node1.Name: {
			"test-pool": {
				v4: cidrSet{netip.MustParsePrefix("10.100.0.0/24"): struct{}{}},
				v6: cidrSet{netip.MustParsePrefix("fd00:100::/96"): struct{}{}},
			},
		},
		node2.Name: {
			"test-pool": {
				v4: cidrSet{netip.MustParsePrefix("10.100.1.0/24"): struct{}{}},
				v6: cidrSet{netip.MustParsePrefix("fd00:100::1:0:0/96"): struct{}{}},
			},
		},
	}, p.orphans)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.0.0/24", "fd00:100::/96"),
	}, p.AllocatedPools(node1.Name))
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.1.0/24", "fd00:100::1:0:0/96"),
	}, p.AllocatedPools(node2.Name))

	// insert again "test-pool"
	err = p.UpsertPool("test-pool",
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("10.100.0.0/16")}}, 24,
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("fd00:100::/80")}}, 96,
	)
	require.NoError(t, err)

	// orphaned cidrs should be un-orphaned
	require.Equal(t, poolToCIDRs{
		"test-pool": {
			v4: cidrSet{netip.MustParsePrefix("10.100.0.0/24"): struct{}{}},
			v6: cidrSet{netip.MustParsePrefix("fd00:100::/96"): struct{}{}},
		},
	}, p.nodes[node1.Name])
	require.Equal(t, poolToCIDRs{
		"test-pool": {
			v4: cidrSet{netip.MustParsePrefix("10.100.1.0/24"): struct{}{}},
			v6: cidrSet{netip.MustParsePrefix("fd00:100::1:0:0/96"): struct{}{}},
		},
	}, p.nodes[node2.Name])
	require.Empty(t, p.orphans)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.0.0/24", "fd00:100::/96"),
	}, p.AllocatedPools(node1.Name))
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.1.0/24", "fd00:100::1:0:0/96"),
	}, p.AllocatedPools(node2.Name))

	// remove v4 CIDRs from "test-pool"
	err = p.UpsertPool("test-pool",
		nil, 24,
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("fd00:100::/80")}}, 96,
	)
	require.NoError(t, err)

	// all previously allocated v4 CIDRs are now orphaned
	require.Equal(t, poolToCIDRs{
		"test-pool": {
			v4: cidrSet{},
			v6: cidrSet{netip.MustParsePrefix("fd00:100::/96"): struct{}{}},
		},
	}, p.nodes[node1.Name])
	require.Equal(t, poolToCIDRs{
		"test-pool": {
			v4: cidrSet{},
			v6: cidrSet{netip.MustParsePrefix("fd00:100::1:0:0/96"): struct{}{}},
		},
	}, p.nodes[node2.Name])
	require.Equal(t, map[string]poolToCIDRs{
		node1.Name: {
			"test-pool": {
				v4: cidrSet{netip.MustParsePrefix("10.100.0.0/24"): struct{}{}},
			},
		},
		node2.Name: {
			"test-pool": {
				v4: cidrSet{netip.MustParsePrefix("10.100.1.0/24"): struct{}{}},
			},
		},
	}, p.orphans)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.0.0/24", "fd00:100::/96"),
	}, p.AllocatedPools(node1.Name))
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.1.0/24", "fd00:100::1:0:0/96"),
	}, p.AllocatedPools(node2.Name))

	// allocate to node3 from test-pool, but v4 CIDR allocation should fail
	err = p.AllocateToNode(node3.Name, node3.Spec.IPAM.Pools)
	require.ErrorIs(t, err, errPoolEmpty)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "fd00:100::2:0:0/96"),
	}, p.AllocatedPools(node3.Name))

	// update "test-pool" to restore v4 CIDRs
	err = p.UpsertPool("test-pool",
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("10.100.0.0/16")}}, 24,
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("fd00:100::/80")}}, 96,
	)
	require.NoError(t, err)

	// orphaned cidrs should be un-orphaned and allocated again to nodes
	require.Equal(t, poolToCIDRs{
		"test-pool": {
			v4: cidrSet{netip.MustParsePrefix("10.100.0.0/24"): struct{}{}},
			v6: cidrSet{netip.MustParsePrefix("fd00:100::/96"): struct{}{}},
		},
	}, p.nodes[node1.Name])
	require.Equal(t, poolToCIDRs{
		"test-pool": {
			v4: cidrSet{netip.MustParsePrefix("10.100.1.0/24"): struct{}{}},
			v6: cidrSet{netip.MustParsePrefix("fd00:100::1:0:0/96"): struct{}{}},
		},
	}, p.nodes[node2.Name])
	require.Empty(t, p.orphans)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.0.0/24", "fd00:100::/96"),
	}, p.AllocatedPools(node1.Name))
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.1.0/24", "fd00:100::1:0:0/96"),
	}, p.AllocatedPools(node2.Name))

	// allocate again to node3 from test-pool, now it should succeed for v4 too
	err = p.AllocateToNode(node3.Name, node3.Spec.IPAM.Pools)
	require.NoError(t, err)

	require.Equal(t, poolToCIDRs{
		"test-pool": {
			v4: cidrSet{netip.MustParsePrefix("10.100.2.0/24"): struct{}{}},
			v6: cidrSet{netip.MustParsePrefix("fd00:100::3:0:0/96"): struct{}{}},
		},
	}, p.nodes[node3.Name])
	require.Empty(t, p.orphans)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.2.0/24", "fd00:100::3:0:0/96"),
	}, p.AllocatedPools(node3.Name))
}

func TestOrphanCIDRsNotStolenFromAnotherPool(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t), true, true)

	// no pools available
	require.Empty(t, p.pools)

	// node1 requested allocations from test-pool in a previous operator run
	node1 := testNode("node1",
		[]ipamTypes.IPAMPoolRequest{request("test-pool", 10, 10)},
		[]ipamTypes.IPAMPoolAllocation{allocation("test-pool", "10.100.0.0/24", "fd00:100::/96")},
	)

	// Mark as ready
	p.RestoreFinished()

	// try to allocate to the node: it should fail, but previous CIDRs should be marked orphans
	err := p.AllocateToNode(node1.Name, node1.Spec.IPAM.Pools)
	require.ErrorContains(t, err, `failed to allocate ipv4 address for node "node1" from pool "test-pool"`)
	require.ErrorContains(t, err, `cannot allocate from non-existing pool: test-pool`)

	require.Equal(t, poolToCIDRs{
		"test-pool": {
			v4: cidrSet{netip.MustParsePrefix("10.100.0.0/24"): struct{}{}},
			v6: cidrSet{netip.MustParsePrefix("fd00:100::/96"): struct{}{}},
		},
	}, p.orphans[node1.Name])
	require.Empty(t, p.nodes[node1.Name])
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.0.0/24", "fd00:100::/96"),
	}, p.AllocatedPools(node1.Name))

	// upsert new pool "another-test-pool" that contains orphan CIDRs from "test-pool"
	// this should fail, since we don't allow another pool to "steal" orphan CIDRs
	err = p.UpsertPool("another-test-pool",
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("10.100.0.0/16")}}, 24,
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("fd00:100::/80")}}, 96,
	)
	require.ErrorContains(t, err, `unable to mark orphaned CIDR 10.100.0.0/24 still used by node node1 as allocated`)
	require.ErrorContains(t, err, `cannot reuse from non-existing pool: test-pool`)

	// restore the original "test-pool"
	// this should succeed, and it should unorphan the CIDRs
	err = p.UpsertPool("test-pool",
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("10.100.0.0/16")}}, 24,
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("fd00:100::/80")}}, 96,
	)
	require.NoError(t, err)

	require.Empty(t, p.orphans[node1.Name])
	require.Equal(t, poolToCIDRs{
		"test-pool": {
			v4: cidrSet{netip.MustParsePrefix("10.100.0.0/24"): struct{}{}},
			v6: cidrSet{netip.MustParsePrefix("fd00:100::/96"): struct{}{}},
		},
	}, p.nodes[node1.Name])
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.100.0.0/24", "fd00:100::/96"),
	}, p.AllocatedPools(node1.Name))
}

func TestUpdatePoolKeepOldCIDRs(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t), true, true)

	err := p.UpsertPool("test-pool",
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("10.0.0.0/28")},
			{cidr: netip.MustParsePrefix("10.0.0.16/28")},
			{cidr: netip.MustParsePrefix("10.0.0.32/28")},
			{cidr: netip.MustParsePrefix("10.0.0.48/28")},
		}, 28,
		nil, 0,
	)
	require.NoError(t, err)

	node := testNode("node",
		[]ipamTypes.IPAMPoolRequest{request("test-pool", 48, 0)},
		nil,
	)

	p.RestoreFinished()

	err = p.AllocateToNode(node.Name, node.Spec.IPAM.Pools)
	require.NoError(t, err)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.0.0.0/28", "10.0.0.16/28",
			"10.0.0.32/28", "10.0.0.48/28"),
	}, p.AllocatedPools(node.Name))

	err = p.UpsertPool("test-pool",
		[]poolCIDRConfig{
			{cidr: netip.MustParsePrefix("10.0.0.0/28")},
			{cidr: netip.MustParsePrefix("10.0.0.16/28")},
		}, 28,
		nil, 0,
	)
	require.NoError(t, err)
	pool := p.pools["test-pool"]
	require.True(t, pool.hasCIDR(netip.MustParsePrefix("10.0.0.0/28")))
	require.True(t, pool.hasCIDR(netip.MustParsePrefix("10.0.0.16/28")))
	require.False(t, pool.hasCIDR(netip.MustParsePrefix("10.0.0.32/28")))
	require.False(t, pool.hasCIDR(netip.MustParsePrefix("10.0.0.48/28")))
}

func TestPoolAllocator_ReservedRangesExcludeCIDRs(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t), true, false)

	err := p.UpsertPool("test-pool",
		[]poolCIDRConfig{
			{
				cidr: netip.MustParsePrefix("10.0.0.0/16"),
				reservedRanges: []netipx.IPRange{
					netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("10.0.0.20")),
				},
			},
		},
		24,
		nil,
		0,
	)
	require.NoError(t, err)

	node := testNode("node",
		[]ipamTypes.IPAMPoolRequest{request("test-pool", 1, 0)},
		nil,
	)

	p.RestoreFinished()

	err = p.AllocateToNode(node.Name, node.Spec.IPAM.Pools)
	require.NoError(t, err)

	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.0.1.0/24"),
	}, p.AllocatedPools(node.Name))
}

func TestPoolAllocator_ReservedRangesCanBeRemoved(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t), true, false)

	err := p.UpsertPool("test-pool",
		[]poolCIDRConfig{
			{
				cidr: netip.MustParsePrefix("10.0.0.0/30"),
				reservedRanges: []netipx.IPRange{
					netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("10.0.0.1")),
				},
			},
		},
		31,
		nil,
		0,
	)
	require.NoError(t, err)
	p.RestoreFinished()

	node1 := testNode("node1",
		[]ipamTypes.IPAMPoolRequest{request("test-pool", 1, 0)},
		nil,
	)

	err = p.AllocateToNode(node1.Name, node1.Spec.IPAM.Pools)
	require.NoError(t, err)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.0.0.2/31"),
	}, p.AllocatedPools(node1.Name))

	err = p.UpsertPool("test-pool",
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("10.0.0.0/30")}},
		31,
		nil,
		0,
	)
	require.NoError(t, err)

	node2 := node1.DeepCopy()
	node2.Name = "node2"

	err = p.AllocateToNode(node2.Name, node2.Spec.IPAM.Pools)
	require.NoError(t, err)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{
		allocation("test-pool", "10.0.0.0/31"),
	}, p.AllocatedPools(node2.Name))
}

func TestPoolAllocator_ReleasedCIDRRemainsReserved(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t), true, false)

	err := p.UpsertPool("test-pool",
		[]poolCIDRConfig{{cidr: netip.MustParsePrefix("10.0.0.0/30")}},
		31,
		nil,
		0,
	)
	require.NoError(t, err)
	p.RestoreFinished()

	request := ipamTypes.IPAMPoolSpec{
		Requested: []ipamTypes.IPAMPoolRequest{request("test-pool", 1, 0)},
	}

	err = p.AllocateToNode("node1", request)
	require.NoError(t, err)
	require.Equal(t,
		cidrSet{netip.MustParsePrefix("10.0.0.0/31"): {}},
		p.nodes["node1"]["test-pool"].v4,
	)

	err = p.UpsertPool("test-pool",
		[]poolCIDRConfig{
			{
				cidr: netip.MustParsePrefix("10.0.0.0/30"),
				reservedRanges: []netipx.IPRange{
					netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("10.0.0.1")),
				},
			},
		},
		31,
		nil,
		0,
	)
	require.NoError(t, err)

	err = p.ReleaseNode("node1")
	require.NoError(t, err)

	err = p.AllocateToNode("node2", request)
	require.NoError(t, err)
	require.Equal(t,
		cidrSet{netip.MustParsePrefix("10.0.0.2/31"): {}},
		p.nodes["node2"]["test-pool"].v4,
	)

	err = p.AllocateToNode("node3", request)
	require.ErrorIs(t, err, errPoolEmpty)
}
