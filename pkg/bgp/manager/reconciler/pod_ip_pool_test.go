// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	bgpTables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	redPoolCIDRv4        = v2alpha1.PoolCIDR("10.0.0.0/16")
	redPoolCIDRv6        = v2alpha1.PoolCIDR("2001:db8::/64")
	redPoolNodePrefix1v4 = iputil.PrefixFrom(netip.MustParsePrefix("10.0.1.0/24"))
	redPoolNodePrefix2v4 = iputil.PrefixFrom(netip.MustParsePrefix("10.0.2.0/24"))
	redPoolNodePrefix1v6 = iputil.PrefixFrom(netip.MustParsePrefix("2001:db8:0:0:1234::/96"))
	redPoolNodePrefix2v6 = iputil.PrefixFrom(netip.MustParsePrefix("2001:db8:0:0:1235::/96"))

	redPoolName       = "red-pool"
	redLabelSelector  = slimv1.LabelSelector{MatchLabels: map[string]string{"pool": "red"}}
	redNameNSSelector = slimv1.LabelSelector{MatchLabels: map[string]string{
		podIPPoolNameLabel: redPoolName,
	}}
	redPool = &v2alpha1.CiliumPodIPPool{
		ObjectMeta: metaV1.ObjectMeta{
			Name:   redPoolName,
			Labels: redLabelSelector.MatchLabels,
		},
		Spec: v2alpha1.IPPoolSpec{
			IPv4: &v2alpha1.IPv4PoolSpec{
				CIDRs:    []v2alpha1.PoolCIDR{redPoolCIDRv4},
				MaskSize: 24,
			},
			IPv6: &v2alpha1.IPv6PoolSpec{
				CIDRs:    []v2alpha1.PoolCIDR{redPoolCIDRv6},
				MaskSize: 96,
			},
		},
	}
	redPeer65001v4PodIPPoolRPName = PolicyStatementName(v2.BGPCiliumPodIPPoolAdvert, redPoolName)
	redPeer65001v4PodIPPoolRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       redPeer65001.Name,
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   PodIPPoolReconcilerPriority,
		Owner:      PodIPPoolReconcilerName,
		Resource:   resource.Key{Name: redPoolName},
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v4PodIPPoolRPName + "-ipv4",
			Conditions: types.RoutePolicyConditions{
				MatchNeighbors: &types.RoutePolicyNeighborMatch{
					Type:      types.RoutePolicyMatchAny,
					Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
				},
				MatchPrefixes: &types.RoutePolicyPrefixMatch{
					Type: types.RoutePolicyMatchAny,
					Prefixes: []types.RoutePolicyPrefix{
						{
							CIDR:         redPoolNodePrefix1v4.Prefix,
							PrefixLenMin: 24,
							PrefixLenMax: 24,
						},
						{
							CIDR:         redPoolNodePrefix2v4.Prefix,
							PrefixLenMin: 24,
							PrefixLenMax: 24,
						},
					},
				},
			},
			Actions: types.RoutePolicyActions{
				RouteAction:    types.RoutePolicyActionAccept,
				AddCommunities: []string{"65000:200"},
			},
		},
	}
	redPeer65001v6PodIPPoolRPName = PolicyStatementName(v2.BGPCiliumPodIPPoolAdvert, redPoolName)
	redPeer65001v6PodIPPoolRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       redPeer65001.Name,
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   PodIPPoolReconcilerPriority,
		Owner:      PodIPPoolReconcilerName,
		Resource:   resource.Key{Name: redPoolName},
		Statement: &types.RoutePolicyStatement{
			Name: redPeer65001v6PodIPPoolRPName + "-ipv6",
			Conditions: types.RoutePolicyConditions{
				MatchNeighbors: &types.RoutePolicyNeighborMatch{
					Type:      types.RoutePolicyMatchAny,
					Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
				},
				MatchPrefixes: &types.RoutePolicyPrefixMatch{
					Type: types.RoutePolicyMatchAny,
					Prefixes: []types.RoutePolicyPrefix{
						{
							CIDR:         redPoolNodePrefix1v6.Prefix,
							PrefixLenMin: 96,
							PrefixLenMax: 96,
						},
						{
							CIDR:         redPoolNodePrefix2v6.Prefix,
							PrefixLenMin: 96,
							PrefixLenMax: 96,
						},
					},
				},
			},
			Actions: types.RoutePolicyActions{
				RouteAction:    types.RoutePolicyActionAccept,
				AddCommunities: []string{"65000:200"},
			},
		},
	}

	bluePoolCIDR1v4       = v2alpha1.PoolCIDR("10.1.0.0/16")
	bluePoolNodePrefix1v4 = iputil.PrefixFrom(netip.MustParsePrefix("10.1.1.0/24"))
	bluePoolCIDR2v4       = v2alpha1.PoolCIDR("10.2.0.0/16")
	bluePoolNodePrefix2v4 = iputil.PrefixFrom(netip.MustParsePrefix("10.2.1.0/24"))
	bluePoolCIDR3v4       = v2alpha1.PoolCIDR("10.3.0.0/16")
	bluePoolCIDR1v6       = v2alpha1.PoolCIDR("2001:db8:1::/64")
	bluePoolNodePrefix1v6 = iputil.PrefixFrom(netip.MustParsePrefix("2001:db8:1:0:1234::/96"))
	bluePoolCIDR2v6       = v2alpha1.PoolCIDR("2001:db8:2::/64")
	bluePoolNodePrefix2v6 = iputil.PrefixFrom(netip.MustParsePrefix("2001:db8:2:0:1234::/96"))
	bluePoolCIDR3v6       = v2alpha1.PoolCIDR("2001:db8:3::/64")

	bluePoolName       = "blue-pool"
	blueLabelSelector  = slimv1.LabelSelector{MatchLabels: map[string]string{"pool": "blue"}}
	blueNameNSSelector = slimv1.LabelSelector{MatchLabels: map[string]string{
		podIPPoolNameLabel: bluePoolName,
	}}
	bluePool = &v2alpha1.CiliumPodIPPool{
		ObjectMeta: metaV1.ObjectMeta{
			Name:   bluePoolName,
			Labels: blueLabelSelector.MatchLabels,
		},
		Spec: v2alpha1.IPPoolSpec{
			IPv4: &v2alpha1.IPv4PoolSpec{
				CIDRs: []v2alpha1.PoolCIDR{
					bluePoolCIDR1v4,
					bluePoolCIDR2v4,
					bluePoolCIDR3v4,
				},
				MaskSize: 24,
			},
			IPv6: &v2alpha1.IPv6PoolSpec{
				CIDRs: []v2alpha1.PoolCIDR{
					bluePoolCIDR1v6,
					bluePoolCIDR2v6,
					bluePoolCIDR3v6,
				},
				MaskSize: 96,
			},
		},
	}
	bluePeer65001v4PodIPPoolRPName = PolicyStatementName(v2.BGPCiliumPodIPPoolAdvert, bluePoolName)
	bluePeer65001v4PodIPPoolRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       bluePeer65001.Name,
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   PodIPPoolReconcilerPriority,
		Owner:      PodIPPoolReconcilerName,
		Resource:   resource.Key{Name: bluePoolName},
		Statement: &types.RoutePolicyStatement{
			Name: bluePeer65001v4PodIPPoolRPName + "-ipv4",
			Conditions: types.RoutePolicyConditions{
				MatchNeighbors: &types.RoutePolicyNeighborMatch{
					Type:      types.RoutePolicyMatchAny,
					Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.2")},
				},
				MatchPrefixes: &types.RoutePolicyPrefixMatch{
					Type: types.RoutePolicyMatchAny,
					Prefixes: []types.RoutePolicyPrefix{
						{
							CIDR:         bluePoolNodePrefix1v4.Prefix,
							PrefixLenMin: 24,
							PrefixLenMax: 24,
						},
						{
							CIDR:         bluePoolNodePrefix2v4.Prefix,
							PrefixLenMin: 24,
							PrefixLenMax: 24,
						},
					},
				},
			},
			Actions: types.RoutePolicyActions{
				RouteAction:    types.RoutePolicyActionAccept,
				AddCommunities: []string{"65355:200"},
			},
		},
	}
	bluePeer65001v6PodIPPoolRPName = PolicyStatementName(v2.BGPCiliumPodIPPoolAdvert, bluePoolName)
	bluePeer65001v6PodIPPoolRP     = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       bluePeer65001.Name,
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   PodIPPoolReconcilerPriority,
		Owner:      PodIPPoolReconcilerName,
		Resource:   resource.Key{Name: bluePoolName},
		Statement: &types.RoutePolicyStatement{
			Name: bluePeer65001v6PodIPPoolRPName + "-ipv6",
			Conditions: types.RoutePolicyConditions{
				MatchNeighbors: &types.RoutePolicyNeighborMatch{
					Type:      types.RoutePolicyMatchAny,
					Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.2")},
				},
				MatchPrefixes: &types.RoutePolicyPrefixMatch{
					Type: types.RoutePolicyMatchAny,
					Prefixes: []types.RoutePolicyPrefix{
						{
							CIDR:         bluePoolNodePrefix1v6.Prefix,
							PrefixLenMin: 96,
							PrefixLenMax: 96,
						},
						{
							CIDR:         bluePoolNodePrefix2v6.Prefix,
							PrefixLenMin: 96,
							PrefixLenMax: 96,
						},
					},
				},
			},
			Actions: types.RoutePolicyActions{
				RouteAction:    types.RoutePolicyActionAccept,
				AddCommunities: []string{"65355:200"},
			},
		},
	}
)

func Test_PodIPPoolAdvertisements(t *testing.T) {
	tests := []struct {
		name                     string
		peerConfig               []*v2.CiliumBGPPeerConfig
		advertisements           []*v2.CiliumBGPAdvertisement
		pools                    []*v2alpha1.CiliumPodIPPool
		preconfiguredPoolAFPaths map[resource.Key]map[types.Family]map[string]struct{}
		preconfiguredRPs         []*bgpTables.DesiredRoutePolicy
		testCiliumNode           *v2.CiliumNode
		testBGPInstanceConfig    *v2.CiliumBGPNodeInstance
		expectedPoolAFPaths      map[resource.Key]map[types.Family]map[string]struct{}
		expectedRPs              []*bgpTables.DesiredRoutePolicy
	}{
		{
			name: "dual stack, advertisement selects pools (by label), pool present on the node",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvertWithSelector(&redLabelSelector),
				blueAdvertWithSelector(&blueLabelSelector),
			},
			pools: []*v2alpha1.CiliumPodIPPool{
				redPool,
				bluePool,
			},
			preconfiguredPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			preconfiguredRPs:         nil,
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: metaV1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						Pools: ipamtypes.IPAMPoolSpec{
							Allocated: []ipamtypes.IPAMPoolAllocation{
								{
									Pool: redPoolName,
									CIDRs: []iputil.Prefix{
										redPoolNodePrefix1v4,
										redPoolNodePrefix2v4,
										redPoolNodePrefix1v6,
										redPoolNodePrefix2v6,
									},
								},
								{
									Pool: bluePoolName,
									CIDRs: []iputil.Prefix{
										bluePoolNodePrefix1v4,
										bluePoolNodePrefix2v4,
										bluePoolNodePrefix1v6,
										bluePoolNodePrefix2v6,
									},
								},
							},
						},
					},
				},
			},

			testBGPInstanceConfig: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v2.CiliumBGPNodePeer{redPeer65001, bluePeer65001},
			},
			expectedPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: redPoolName}: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						redPoolNodePrefix1v4.String(): struct{}{},
						redPoolNodePrefix2v4.String(): struct{}{},
					},
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						redPoolNodePrefix1v6.String(): struct{}{},
						redPoolNodePrefix2v6.String(): struct{}{},
					},
				},
				{Name: bluePoolName}: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						bluePoolNodePrefix1v4.String(): struct{}{},
						bluePoolNodePrefix2v4.String(): struct{}{},
					},
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						bluePoolNodePrefix1v6.String(): struct{}{},
						bluePoolNodePrefix2v6.String(): struct{}{},
					},
				},
			},
			expectedRPs: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4PodIPPoolRP,
				redPeer65001v6PodIPPoolRP,
				bluePeer65001v4PodIPPoolRP,
				bluePeer65001v6PodIPPoolRP,
			},
		},
		{
			name: "dual stack, advertisement selects pools (by nameNS selector), pool present on the node",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvertWithSelector(&redNameNSSelector),
				blueAdvertWithSelector(&blueNameNSSelector),
			},
			pools: []*v2alpha1.CiliumPodIPPool{
				redPool,
				bluePool,
			},
			preconfiguredPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			preconfiguredRPs:         nil,
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: metaV1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						Pools: ipamtypes.IPAMPoolSpec{
							Allocated: []ipamtypes.IPAMPoolAllocation{
								{
									Pool: redPoolName,
									CIDRs: []iputil.Prefix{
										redPoolNodePrefix1v4,
										redPoolNodePrefix2v4,
										redPoolNodePrefix1v6,
										redPoolNodePrefix2v6,
									},
								},
								{
									Pool: bluePoolName,
									CIDRs: []iputil.Prefix{
										bluePoolNodePrefix1v4,
										bluePoolNodePrefix2v4,
										bluePoolNodePrefix1v6,
										bluePoolNodePrefix2v6,
									},
								},
							},
						},
					},
				},
			},

			testBGPInstanceConfig: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v2.CiliumBGPNodePeer{redPeer65001, bluePeer65001},
			},
			expectedPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: redPoolName}: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						redPoolNodePrefix1v4.String(): struct{}{},
						redPoolNodePrefix2v4.String(): struct{}{},
					},
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						redPoolNodePrefix1v6.String(): struct{}{},
						redPoolNodePrefix2v6.String(): struct{}{},
					},
				},
				{Name: bluePoolName}: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						bluePoolNodePrefix1v4.String(): struct{}{},
						bluePoolNodePrefix2v4.String(): struct{}{},
					},
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						bluePoolNodePrefix1v6.String(): struct{}{},
						bluePoolNodePrefix2v6.String(): struct{}{},
					},
				},
			},
			expectedRPs: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4PodIPPoolRP,
				redPeer65001v6PodIPPoolRP,
				bluePeer65001v4PodIPPoolRP,
				bluePeer65001v6PodIPPoolRP,
			},
		},
		{
			name: "dual stack, pool NOT selected by advertisement, pool present on the node",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvert,  // no selector matching red pool
				blueAdvert, // no selector matching blue pool
			},
			pools: []*v2alpha1.CiliumPodIPPool{
				redPool,
				bluePool,
			},
			preconfiguredPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: metaV1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						Pools: ipamtypes.IPAMPoolSpec{
							Allocated: []ipamtypes.IPAMPoolAllocation{
								{
									Pool: redPoolName,
									CIDRs: []iputil.Prefix{
										redPoolNodePrefix1v4,
										redPoolNodePrefix2v4,
										redPoolNodePrefix1v6,
										redPoolNodePrefix2v6,
									},
								},
								{
									Pool: bluePoolName,
									CIDRs: []iputil.Prefix{
										bluePoolNodePrefix1v4,
										bluePoolNodePrefix2v4,
										bluePoolNodePrefix1v6,
										bluePoolNodePrefix2v6,
									},
								},
							},
						},
					},
				},
			},
			testBGPInstanceConfig: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v2.CiliumBGPNodePeer{redPeer65001, bluePeer65001},
			},
			expectedPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			expectedRPs:         nil,
		},
		{
			name: "dual stack, pool selected by advertisement, pool NOT present on the node",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvertWithSelector(&redLabelSelector),
				blueAdvertWithSelector(&blueLabelSelector),
			},
			pools: []*v2alpha1.CiliumPodIPPool{
				redPool,
				bluePool,
			},
			preconfiguredPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: metaV1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						Pools: ipamtypes.IPAMPoolSpec{
							Allocated: []ipamtypes.IPAMPoolAllocation{
								{
									Pool:  redPoolName,
									CIDRs: []iputil.Prefix{},
								},
								{
									Pool:  bluePoolName,
									CIDRs: []iputil.Prefix{},
								},
							},
						},
					},
				},
			},

			testBGPInstanceConfig: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v2.CiliumBGPNodePeer{redPeer65001, bluePeer65001},
			},
			expectedPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			expectedRPs:         nil,
		},
		{
			name: "dual stack, clean up of preconfigured advertisements",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvertWithSelector(&redLabelSelector),
			},
			pools: []*v2alpha1.CiliumPodIPPool{
				redPool,
			},
			preconfiguredPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "unknown"}: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						"10.10.1.0/24": struct{}{},
						"10.10.2.0/24": struct{}{},
					},
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						"2001:db8:100:0:1234::/96": struct{}{},
						"2001:db8:101:0:1234::/96": struct{}{},
					},
				},
			},
			preconfiguredRPs: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4PodIPPoolRP,
				redPeer65001v6PodIPPoolRP,
				bluePeer65001v4PodIPPoolRP,
				bluePeer65001v6PodIPPoolRP,
			},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: metaV1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						Pools: ipamtypes.IPAMPoolSpec{
							Allocated: []ipamtypes.IPAMPoolAllocation{
								{
									Pool: redPoolName,
									CIDRs: []iputil.Prefix{
										redPoolNodePrefix1v4,
										redPoolNodePrefix2v4,
										redPoolNodePrefix1v6,
										redPoolNodePrefix2v6,
									},
								},
							},
						},
					},
				},
			},

			testBGPInstanceConfig: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v2.CiliumBGPNodePeer{redPeer65001, bluePeer65001},
			},
			expectedPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: redPoolName}: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						redPoolNodePrefix1v4.String(): struct{}{},
						redPoolNodePrefix2v4.String(): struct{}{},
					},
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						redPoolNodePrefix1v6.String(): struct{}{},
						redPoolNodePrefix2v6.String(): struct{}{},
					},
				},
			},
			expectedRPs: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4PodIPPoolRP,
				redPeer65001v6PodIPPoolRP,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			db := statedb.New()
			desiredRoutePolicyTable, err := bgpTables.NewDesiredRoutePoliciesTable(db)
			req.NoError(err)

			params := PodIPPoolReconcilerIn{
				Logger: hivetest.Logger(t),
				PeerAdvert: NewCiliumPeerAdvertisement(
					PeerAdvertisementIn{
						Logger:          hivetest.Logger(t),
						PeerConfigStore: store.InitMockStore[*v2.CiliumBGPPeerConfig](tt.peerConfig),
						AdvertStore:     store.InitMockStore[*v2.CiliumBGPAdvertisement](tt.advertisements),
					}),
				PoolStore:               store.InitMockStore[*v2alpha1.CiliumPodIPPool](tt.pools),
				DB:                      db,
				DesiredRoutePolicyTable: desiredRoutePolicyTable,
			}
			podIPPoolReconciler := NewPodIPPoolReconciler(params).Reconciler.(*PodIPPoolReconciler)

			testBGPInstance := instance.NewFakeBGPInstance()
			reconcileParams := ReconcileParams{
				BGPInstance:   testBGPInstance,
				DesiredConfig: tt.testBGPInstanceConfig,
				CiliumNode:    tt.testCiliumNode,
			}

			// set the preconfigured advertisements
			presetPoolAFPaths := make(ResourceAFPathsMap)
			for pool, prePoolAFPaths := range tt.preconfiguredPoolAFPaths {
				presetPoolAFPaths[pool] = make(AFPathsMap)
				for fam, afPaths := range prePoolAFPaths {
					pathSet := make(PathMap)
					for prePath := range afPaths {
						path := types.MustNewPathForPrefix(netip.MustParsePrefix(prePath))
						path.Family = fam
						pathSet[prePath] = path
					}
					presetPoolAFPaths[pool][fam] = pathSet
				}
			}
			podIPPoolReconciler.setMetadata(testBGPInstance, PodIPPoolReconcilerMetadata{
				PoolAFPaths: presetPoolAFPaths,
			})

			// set preconfigured policy entries
			tx := db.WriteTxn(podIPPoolReconciler.desiredRoutePolicyTable)
			defer tx.Abort()
			for _, policy := range tt.preconfiguredRPs {
				_, _, err := podIPPoolReconciler.desiredRoutePolicyTable.Insert(tx, policy)
				require.NoError(t, err)
			}
			tx.Commit()

			// run podIPPoolReconciler twice to ensure idempotency
			for range 2 {
				err := podIPPoolReconciler.Reconcile(context.Background(), reconcileParams)
				req.NoError(err)
			}

			// check if the advertisements are as expected
			runningPoolAFPaths := make(map[resource.Key]map[types.Family]map[string]struct{})
			for pool, poolAFPaths := range podIPPoolReconciler.getMetadata(testBGPInstance).PoolAFPaths {
				runningPoolAFPaths[pool] = make(map[types.Family]map[string]struct{})
				for fam, afPaths := range poolAFPaths {
					pathSet := make(map[string]struct{})
					for pathKey := range afPaths {
						pathSet[pathKey] = struct{}{}
					}
					runningPoolAFPaths[pool][fam] = pathSet
				}
			}

			req.Equal(tt.expectedPoolAFPaths, runningPoolAFPaths)
			requireDesiredRoutePolicies(t, podIPPoolReconciler.db, podIPPoolReconciler.desiredRoutePolicyTable,
				testBGPInstance.Name, podIPPoolReconciler.Name(), tt.expectedRPs)
		})
	}
}
