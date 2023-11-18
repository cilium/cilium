// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"net/netip"
	"testing"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestPodIPPoolReconciler(t *testing.T) {
	blueSelector := slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}}

	pool1Key := resource.Key{Name: "pool-1", Namespace: "default"}
	pool1 := &v2alpha1api.CiliumPodIPPool{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      pool1Key.Name,
			Namespace: pool1Key.Namespace,
			Labels:    blueSelector.MatchLabels,
		},
		Spec: v2alpha1api.IPPoolSpec{
			IPv4: &v2alpha1api.IPv4PoolSpec{
				CIDRs:    []v2alpha1api.PoolCIDR{"10.0.0.0/16"},
				MaskSize: 24,
			},
			IPv6: &v2alpha1api.IPv6PoolSpec{
				CIDRs:    []v2alpha1api.PoolCIDR{"2001:0:0:1234::/64"},
				MaskSize: 96,
			},
		},
	}

	nsNameSelector := slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			podIPPoolNamespaceLabel: pool1.Namespace,
			podIPPoolNameLabel:      pool1.Name,
		},
	}

	pool2Key := resource.Key{Name: "pool-2", Namespace: "default"}
	pool2 := &v2alpha1api.CiliumPodIPPool{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      pool2Key.Name,
			Namespace: pool2Key.Namespace,
			Labels:    blueSelector.MatchLabels,
		},
		Spec: v2alpha1api.IPPoolSpec{
			IPv4: &v2alpha1api.IPv4PoolSpec{
				CIDRs: []v2alpha1api.PoolCIDR{
					"20.0.0.0/16",
					"30.0.0.0/16",
					"40.0.0.0/16",
				},
				MaskSize: 24,
			},
			IPv6: &v2alpha1api.IPv6PoolSpec{
				CIDRs: []v2alpha1api.PoolCIDR{
					"2002:0:0:1234::/64",
					"2003:0:0:1234::/64",
					"2004:0:0:1234::/64",
				},
				MaskSize: 96,
			},
		},
	}

	var table = []struct {
		// name of the test case
		name string
		// The pod IP pools allocated to the local node
		nodeAllocs []ipamtypes.IPAMPoolAllocation
		// The pool selector of the vRouter
		poolSelector *slim_metav1.LabelSelector
		// the pools which will be "upserted" in the diffstore
		upsertedPools []*v2alpha1api.CiliumPodIPPool
		// the updated pool CIDR blocks to reconcile
		updated map[resource.Key][]string
		// error nil or not
		err error
	}{
		{
			name:          "no matching node cidrs from pool",
			nodeAllocs:    nil,
			poolSelector:  &blueSelector,
			upsertedPools: []*v2alpha1api.CiliumPodIPPool{pool1},
			updated:       map[resource.Key][]string{},
		},
		{
			name: "match one ipv4 cidr from one pool using special purpose selector",
			nodeAllocs: []ipamtypes.IPAMPoolAllocation{
				{
					Pool:  pool1.Name,
					CIDRs: []ipamtypes.IPAMPodCIDR{"10.0.1.0/24"},
				},
			},
			poolSelector:  &nsNameSelector,
			upsertedPools: []*v2alpha1api.CiliumPodIPPool{pool1},
			updated:       map[resource.Key][]string{pool1Key: {"10.0.1.0/24"}},
		},
		{
			name: "match one ipv4 cidr from one pool",
			nodeAllocs: []ipamtypes.IPAMPoolAllocation{
				{
					Pool:  pool1.Name,
					CIDRs: []ipamtypes.IPAMPodCIDR{"10.0.1.0/24"},
				},
			},
			poolSelector:  &blueSelector,
			upsertedPools: []*v2alpha1api.CiliumPodIPPool{pool1},
			updated:       map[resource.Key][]string{pool1Key: {"10.0.1.0/24"}},
		},
		{
			name: "match one ipv6 cidr from one pool",
			nodeAllocs: []ipamtypes.IPAMPoolAllocation{
				{
					Pool: pool1.Name,
					CIDRs: []ipamtypes.IPAMPodCIDR{
						"2001:0:0:1234:5678::/96",
					},
				},
			},
			poolSelector:  &blueSelector,
			upsertedPools: []*v2alpha1api.CiliumPodIPPool{pool1},
			updated:       map[resource.Key][]string{pool1Key: {"2001:0:0:1234:5678::/96"}},
		},
		{
			name: "match multiple ipv4 and ipv6 cidrs from one pool",
			nodeAllocs: []ipamtypes.IPAMPoolAllocation{
				{
					Pool: pool1.Name,
					CIDRs: []ipamtypes.IPAMPodCIDR{
						"10.0.1.0/24",
						"10.0.2.0/24",
						"10.0.3.0/24",
						"2001:0:0:1234:5678::/96",
						"2001:0:0:1234:5679::/96",
						"2001:0:0:1234:5680::/96",
					},
				},
			},
			poolSelector:  &blueSelector,
			upsertedPools: []*v2alpha1api.CiliumPodIPPool{pool1},
			updated: map[resource.Key][]string{
				pool1Key: {
					"10.0.1.0/24",
					"10.0.2.0/24",
					"10.0.3.0/24",
					"2001:0:0:1234:5678::/96",
					"2001:0:0:1234:5679::/96",
					"2001:0:0:1234:5680::/96",
				},
			},
		},
		{
			name: "match multiple ipv4 and ipv6 cidrs from two pools",
			nodeAllocs: []ipamtypes.IPAMPoolAllocation{
				{
					Pool: pool1.Name,
					CIDRs: []ipamtypes.IPAMPodCIDR{
						"10.0.1.0/24",
						"10.0.2.0/24",
						"2001:0:0:1234:5678::/96",
						"2001:0:0:1234:5679::/96",
					},
				},
				{
					Pool: pool2.Name,
					CIDRs: []ipamtypes.IPAMPodCIDR{
						"20.0.1.0/24",
						"30.0.1.0/24",
						"2002:0:0:1234:5678::/96",
						"2003:0:0:1234:5678::/96",
					},
				},
			},
			poolSelector:  &blueSelector,
			upsertedPools: []*v2alpha1api.CiliumPodIPPool{pool1, pool2},
			updated: map[resource.Key][]string{
				pool1Key: {
					"10.0.1.0/24",
					"10.0.2.0/24",
					"2001:0:0:1234:5678::/96",
					"2001:0:0:1234:5679::/96",
				},
				pool2Key: {
					"20.0.1.0/24",
					"30.0.1.0/24",
					"2002:0:0:1234:5678::/96",
					"2003:0:0:1234:5678::/96",
				},
			},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// Setup the test server, create a bgp virtual router, and upsert the test pools
			// into the diff store.
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			testSC, err := NewServerWithConfig(context.Background(), srvParams)
			if err != nil {
				t.Fatalf("failed to create test bgp server: %v", err)
			}
			testSC.Config = &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:          64125,
				Neighbors:         []v2alpha1api.CiliumBGPNeighbor{},
				PodIPPoolSelector: tt.poolSelector,
			}

			// Setup the pool reconciler, local node, CiliumNode, and assign test
			// pools to CiliumNode.
			store := newMockBGPCPResourceStore[*v2alpha1api.CiliumPodIPPool]()
			for _, obj := range tt.upsertedPools {
				store.Upsert(obj)
			}
			reconciler := NewPodIPPoolReconciler(store).Reconciler.(*PodIPPoolReconciler)

			node := &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "node1",
					Namespace: "default",
				},
			}

			if tt.nodeAllocs != nil {
				node.Spec.IPAM.Pools.Allocated = append(node.Spec.IPAM.Pools.Allocated, tt.nodeAllocs...)
			}
			err = reconciler.Reconcile(context.Background(), ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: testSC.Config,
				CiliumNode:    node,
			})
			if err != nil {
				t.Fatalf("failed to reconcile pool cidr advertisements: %v", err)
			}

			podIPPoolAnnouncements := reconciler.getMetadata(testSC)

			// If the pool selector is disabled, ensure no advertisements are still present.
			if tt.poolSelector == nil && tt.upsertedPools != nil {
				if len(podIPPoolAnnouncements) > 0 {
					t.Fatal("disabled pool selector but pool cidr advertisements still present")
				}
			}

			log.Printf("%+v %+v", podIPPoolAnnouncements, tt.updated)

			// Ensure we see tt.updated in testSC.PodIPPoolAnnouncements
			for poolKey, cidrs := range tt.updated {
				for _, cidr := range cidrs {
					prefix := netip.MustParsePrefix(cidr)
					var seen bool
					for _, advrt := range podIPPoolAnnouncements[poolKey] {
						if advrt.NLRI.String() == prefix.String() {
							seen = true
						}
					}
					if !seen {
						t.Fatalf("failed to advertise %v", cidr)
					}
				}
			}

			// ensure testSC.PodIPPoolAnnouncements does not contain advertisements
			// not in tt.updated
			for poolKey, advrts := range podIPPoolAnnouncements {
				for _, advrt := range advrts {
					var seen bool
					for _, cidr := range tt.updated[poolKey] {
						if advrt.NLRI.String() == cidr {
							seen = true
						}
					}
					if !seen {
						t.Fatalf("unwanted advert %+v", advrt)
					}
				}
			}

		})
	}
}
