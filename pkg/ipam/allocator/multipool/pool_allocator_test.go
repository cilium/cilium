// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"math/big"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestPoolAllocator(t *testing.T) {
	p := NewPoolAllocator()
	err := p.AddPool("default",
		[]string{"10.100.0.0/16", "10.200.0.0/16"}, 24,
		[]string{"fd00:100::/80", "fc00:100::/80"}, 96,
	)
	assert.NoError(t, err)

	// node1 is a node which has some previously allocated CIDRs
	node1 := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Requested: []ipamTypes.IPAMPoolRequest{
						{
							Pool: "default",
							Needed: ipamTypes.IPAMPoolDemand{
								IPv4Addrs: 10,
								IPv6Addrs: 10,
							},
						},
					},
					Allocated: []ipamTypes.IPAMPoolAllocation{
						{
							Pool: "default",
							CIDRs: []ipamTypes.IPAMPodCIDR{
								"fd00:100:0:0:0:10::/96",
								"10.100.20.0/24",
								"10.100.10.0/24",
							},
						},
					},
				},
			},
		},
	}
	// node2 is a new node which needs a fresh allocation
	node2 := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Requested: []ipamTypes.IPAMPoolRequest{
						{
							Pool: "default",
							Needed: ipamTypes.IPAMPoolDemand{
								IPv4Addrs: 10,
								IPv6Addrs: 10,
							},
						},
					},
				},
			},
		},
	}
	// node3 is a new node which is attempting to steal a CIDR from node1
	node3 := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node3",
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Allocated: []ipamTypes.IPAMPoolAllocation{
						{
							Pool: "default",
							CIDRs: []ipamTypes.IPAMPodCIDR{
								"10.100.10.0/24", // already allocated to node1
							},
						},
					},
				},
			},
		},
	}
	// node1 has some pre-allocated pools that need to be restored
	err = p.AllocateToNode(node1)
	assert.ErrorIs(t, ErrAllocatorNotReady, err)
	assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []ipamTypes.IPAMPodCIDR{ // must be sorted
				"10.100.10.0/24",
				"10.100.20.0/24",
				"fd00:100::10:0:0/96",
			},
		},
	}, p.AllocatedPools(node1.Name))

	// node2 must not allocate before restoration has finished
	err = p.AllocateToNode(node2)
	assert.ErrorIs(t, ErrAllocatorNotReady, err)
	assert.Empty(t, p.AllocatedPools(node2.Name))

	// node3 must not steal the restored CIDR from node1
	err = p.AllocateToNode(node3)
	assert.ErrorIs(t, ErrAllocatorNotReady, err)
	assert.Empty(t, p.AllocatedPools(node3.Name))

	// Mark as ready
	p.RestoreFinished()

	// The following is a no-op, but should not return any errors
	err = p.AllocateToNode(node1)
	assert.NoError(t, err)
	node1.Spec.IPAM.Pools.Allocated = p.AllocatedPools(node1.Name)
	assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []ipamTypes.IPAMPodCIDR{ // must be sorted
				"10.100.10.0/24",
				"10.100.20.0/24",
				"fd00:100::10:0:0/96",
			},
		},
	}, node1.Spec.IPAM.Pools.Allocated)

	// The following should allocate one IPv4 and IPv6 CIDR each to node2
	err = p.AllocateToNode(node2)
	assert.NoError(t, err)
	node2.Spec.IPAM.Pools.Allocated = p.AllocatedPools(node2.Name)
	assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []ipamTypes.IPAMPodCIDR{
				"10.100.0.0/24",
				"fd00:100::/96",
			},
		},
	}, node2.Spec.IPAM.Pools.Allocated)

	// The following should be rejected, because the CIDR is owned by node1
	err = p.AllocateToNode(node3)
	assert.EqualError(t, err, "unable to reuse from pool default: cidr 10.100.10.0/24 has already been allocated")
	assert.Empty(t, p.AllocatedPools(node3.Name))

	// Release 10.100.10.0/24 from node1
	node1.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []ipamTypes.IPAMPodCIDR{
				"10.100.20.0/24",
				"fd00:100::10:0:0/96",
			},
		},
	}
	err = p.AllocateToNode(node1)
	assert.NoError(t, err)
	assert.Equal(t, node1.Spec.IPAM.Pools.Allocated, p.AllocatedPools(node1.Name))

	// node3 can now allocate 10.100.10.0/24
	err = p.AllocateToNode(node3)
	assert.NoError(t, err)
	node3.Spec.IPAM.Pools.Allocated = p.AllocatedPools(node3.Name)
	assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []ipamTypes.IPAMPodCIDR{
				"10.100.10.0/24",
			},
		},
	}, node3.Spec.IPAM.Pools.Allocated)

	// Release node2
	err = p.ReleaseNode(node2.Name)
	assert.NoError(t, err)
	assert.Empty(t, p.AllocatedPools(node2.Name))

	// Try to allocate released CIDR from node2 to node3
	node3.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []ipamTypes.IPAMPodCIDR{
				"10.100.0.0/24",
				"10.100.10.0/24",
			},
		},
	}
	err = p.AllocateToNode(node3)
	assert.NoError(t, err)
	assert.Equal(t, node3.Spec.IPAM.Pools.Allocated, p.AllocatedPools(node3.Name))

	// Increase demand for node1, this should allocate a new CIDR
	node1.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
		{
			Pool: "default",
			Needed: ipamTypes.IPAMPoolDemand{
				IPv4Addrs: 300,
				IPv6Addrs: 10,
			},
		},
	}
	err = p.AllocateToNode(node1)
	assert.NoError(t, err)
	node1.Spec.IPAM.Pools.Allocated = p.AllocatedPools(node1.Name)
	assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []ipamTypes.IPAMPodCIDR{
				"10.100.1.0/24",
				"10.100.20.0/24",
				"fd00:100::10:0:0/96",
			},
		},
	}, node1.Spec.IPAM.Pools.Allocated)
}

func TestPoolAllocator_PoolErrors(t *testing.T) {
	p := NewPoolAllocator()
	p.RestoreFinished()

	node := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Requested: []ipamTypes.IPAMPoolRequest{
						{
							Pool: "no-exist",
							Needed: ipamTypes.IPAMPoolDemand{
								IPv4Addrs: 10,
							},
						},
					},
				},
			},
		},
	}

	err := p.AllocateToNode(node)
	assert.ErrorContains(t, err, `failed to allocate ipv4 address for node "node1" from pool "no-exist"`)
	assert.ErrorContains(t, err, `cannot allocate from non-existing pool: no-exist`)

	err = p.AddPool("ipv4-only",
		[]string{"10.0.0.0/16"}, 24,
		nil, 0,
	)
	assert.NoError(t, err)
	node.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
		{
			Pool: "ipv4-only",
			Needed: ipamTypes.IPAMPoolDemand{
				IPv6Addrs: 10,
			},
		},
	}
	err = p.AllocateToNode(node)
	assert.ErrorContains(t, err, `failed to allocate ipv6 address for node "node1" from pool "ipv4-only"`)
	assert.ErrorContains(t, err, `pool empty`)

	err = p.AddPool("ipv4-only-same-cidr",
		[]string{"10.0.0.0/16"}, 24,
		nil, 0,
	)
	assert.NoError(t, err)
	err = p.AddPool("ipv6-only",
		nil, 0,
		[]string{"fd00:100::/80"}, 96,
	)
	assert.NoError(t, err)
	node.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{
		{
			Pool: "ipv4-only",
			Needed: ipamTypes.IPAMPoolDemand{
				IPv4Addrs: 10,
				IPv6Addrs: 10,
			},
		},
		{
			Pool: "ipv4-only-same-cidr",
			Needed: ipamTypes.IPAMPoolDemand{
				IPv4Addrs: 10,
				IPv6Addrs: 10,
			},
		},
		{
			Pool: "ipv6-only",
			Needed: ipamTypes.IPAMPoolDemand{
				IPv4Addrs: 10,
				IPv6Addrs: 10,
			},
		},
	}
	err = p.AllocateToNode(node)
	assert.ErrorContains(t, err, `failed to allocate ipv6 address for node "node1" from pool "ipv4-only"`)
	assert.ErrorContains(t, err, `failed to allocate ipv6 address for node "node1" from pool "ipv4-only-same-cidr"`)
	assert.ErrorContains(t, err, `failed to allocate ipv4 address for node "node1" from pool "ipv6-only"`)
	assert.ErrorContains(t, err, `pool empty`)
	// Some allocations will have failed, but we still expect everything else to have succeeded
	node.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "ipv4-only",
			CIDRs: []ipamTypes.IPAMPodCIDR{
				"10.0.0.0/24",
			},
		},
		{
			Pool: "ipv4-only-same-cidr",
			CIDRs: []ipamTypes.IPAMPodCIDR{
				"10.0.0.0/24",
			},
		},
		{
			Pool: "ipv6-only",
			CIDRs: []ipamTypes.IPAMPodCIDR{
				"fd00:100::/96",
			},
		},
	}
	assert.Equal(t, node.Spec.IPAM.Pools.Allocated, p.AllocatedPools(node.Name))

	// Try to occupy invalid CIDR
	node.Spec.IPAM.Pools.Allocated[0] = ipamTypes.IPAMPoolAllocation{
		Pool: "ipv4-only",
		CIDRs: []ipamTypes.IPAMPodCIDR{
			"10.0.0.0/24",
			"333.444.555.666/77",
		},
	}
	err = p.AllocateToNode(node)
	assert.ErrorContains(t, err, `failed to parse CIDR of pool "ipv4-only"`)
}

func Test_addrsInPrefix(t *testing.T) {
	mustParseBigInt := func(s string) *big.Int {
		r := new(big.Int)
		r.SetString(s, 0)
		return r
	}

	tests := []struct {
		name string
		args netip.Prefix
		want *big.Int
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
			name: "two",
			args: netip.MustParsePrefix("10.0.0.0/30"),
			want: big.NewInt(2),
		},
		{
			name: "underflow /31",
			args: netip.MustParsePrefix("10.0.0.0/31"),
			want: big.NewInt(0),
		},
		{
			name: "underflow /32",
			args: netip.MustParsePrefix("10.0.0.0/32"),
			want: big.NewInt(0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addrsInPrefix(tt.args); got.Cmp(tt.want) != 0 {
				t.Errorf("addrsInPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}
