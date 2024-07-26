// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	podIPPoolTestLogger = logrus.WithField("unit_test", "reconcilerv2_podippool")
)

var (
	redPoolCIDRv4        = v2alpha1.PoolCIDR("10.0.0.0/16")
	redPoolCIDRv6        = v2alpha1.PoolCIDR("2001:db8::/64")
	redPoolNodePrefix1v4 = ipamtypes.IPAMPodCIDR("10.0.1.0/24")
	redPoolNodePrefix2v4 = ipamtypes.IPAMPodCIDR("10.0.2.0/24")
	redPoolNodePrefix1v6 = ipamtypes.IPAMPodCIDR("2001:db8:0:0:1234::/96")
	redPoolNodePrefix2v6 = ipamtypes.IPAMPodCIDR("2001:db8:0:0:1235::/96")

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
	redPeer65001v4PodIPPoolRPName = PolicyName("red-peer-65001", "ipv4", v2alpha1.BGPCiliumPodIPPoolAdvert, redPoolName)
	redPeer65001v4PodIPPoolRP     = &types.RoutePolicy{
		Name: redPeer65001v4PodIPPoolRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(string(redPoolNodePrefix1v4)),
							PrefixLenMin: 24,
							PrefixLenMax: 24,
						},
						{
							CIDR:         netip.MustParsePrefix(string(redPoolNodePrefix2v4)),
							PrefixLenMin: 24,
							PrefixLenMax: 24,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65000:200"},
				},
			},
		},
	}
	redPeer65001v6PodIPPoolRPName = PolicyName("red-peer-65001", "ipv6", v2alpha1.BGPCiliumPodIPPoolAdvert, redPoolName)
	redPeer65001v6PodIPPoolRP     = &types.RoutePolicy{
		Name: redPeer65001v6PodIPPoolRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(string(redPoolNodePrefix1v6)),
							PrefixLenMin: 96,
							PrefixLenMax: 96,
						},
						{
							CIDR:         netip.MustParsePrefix(string(redPoolNodePrefix2v6)),
							PrefixLenMin: 96,
							PrefixLenMax: 96,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65000:200"},
				},
			},
		},
	}

	bluePoolCIDR1v4       = v2alpha1.PoolCIDR("10.1.0.0/16")
	bluePoolNodePrefix1v4 = ipamtypes.IPAMPodCIDR("10.1.1.0/24")
	bluePoolCIDR2v4       = v2alpha1.PoolCIDR("10.2.0.0/16")
	bluePoolNodePrefix2v4 = ipamtypes.IPAMPodCIDR("10.2.1.0/24")
	bluePoolCIDR3v4       = v2alpha1.PoolCIDR("10.3.0.0/16")
	bluePoolCIDR1v6       = v2alpha1.PoolCIDR("2001:db8:1::/64")
	bluePoolNodePrefix1v6 = ipamtypes.IPAMPodCIDR("2001:db8:1:0:1234::/96")
	bluePoolCIDR2v6       = v2alpha1.PoolCIDR("2001:db8:2::/64")
	bluePoolNodePrefix2v6 = ipamtypes.IPAMPodCIDR("2001:db8:2:0:1234::/96")
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
	bluePeer65001v4PodIPPoolRPName = PolicyName("blue-peer-65001", "ipv4", v2alpha1.BGPCiliumPodIPPoolAdvert, bluePoolName)
	bluePeer65001v4PodIPPoolRP     = &types.RoutePolicy{
		Name: bluePeer65001v4PodIPPoolRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.2/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(string(bluePoolNodePrefix1v4)),
							PrefixLenMin: 24,
							PrefixLenMax: 24,
						},
						{
							CIDR:         netip.MustParsePrefix(string(bluePoolNodePrefix2v4)),
							PrefixLenMin: 24,
							PrefixLenMax: 24,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65355:200"},
				},
			},
		},
	}
	bluePeer65001v6PodIPPoolRPName = PolicyName("blue-peer-65001", "ipv6", v2alpha1.BGPCiliumPodIPPoolAdvert, bluePoolName)
	bluePeer65001v6PodIPPoolRP     = &types.RoutePolicy{
		Name: bluePeer65001v6PodIPPoolRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.2/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(string(bluePoolNodePrefix1v6)),
							PrefixLenMin: 96,
							PrefixLenMax: 96,
						},
						{
							CIDR:         netip.MustParsePrefix(string(bluePoolNodePrefix2v6)),
							PrefixLenMin: 96,
							PrefixLenMax: 96,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65355:200"},
				},
			},
		},
	}
)

func Test_PodIPPoolAdvertisements(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name                     string
		peerConfig               []*v2alpha1.CiliumBGPPeerConfig
		advertisements           []*v2alpha1.CiliumBGPAdvertisement
		pools                    []*v2alpha1.CiliumPodIPPool
		preconfiguredPoolAFPaths map[resource.Key]map[types.Family]map[string]struct{}
		preconfiguredRPs         ResourceRoutePolicyMap
		testCiliumNode           *v2api.CiliumNode
		testBGPInstanceConfig    *v2alpha1.CiliumBGPNodeInstance
		expectedPoolAFPaths      map[resource.Key]map[types.Family]map[string]struct{}
		expectedRPs              ResourceRoutePolicyMap
	}{
		{
			name: "dual stack, advertisement selects pools (by label), pool present on the node",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvertWithSelector(&redLabelSelector),
				blueAdvertWithSelector(&blueLabelSelector),
			},
			pools: []*v2alpha1.CiliumPodIPPool{
				redPool,
				bluePool,
			},
			preconfiguredPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			preconfiguredRPs:         ResourceRoutePolicyMap{},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: metaV1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						Pools: ipamtypes.IPAMPoolSpec{
							Allocated: []ipamtypes.IPAMPoolAllocation{
								{
									Pool: redPoolName,
									CIDRs: []ipamtypes.IPAMPodCIDR{
										redPoolNodePrefix1v4,
										redPoolNodePrefix2v4,
										redPoolNodePrefix1v6,
										redPoolNodePrefix2v6,
									},
								},
								{
									Pool: bluePoolName,
									CIDRs: []ipamtypes.IPAMPodCIDR{
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

			testBGPInstanceConfig: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v2alpha1.CiliumBGPNodePeer{redPeer65001, bluePeer65001},
			},
			expectedPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: redPoolName}: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						string(redPoolNodePrefix1v4): struct{}{},
						string(redPoolNodePrefix2v4): struct{}{},
					},
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						string(redPoolNodePrefix1v6): struct{}{},
						string(redPoolNodePrefix2v6): struct{}{},
					},
				},
				{Name: bluePoolName}: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						string(bluePoolNodePrefix1v4): struct{}{},
						string(bluePoolNodePrefix2v4): struct{}{},
					},
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						string(bluePoolNodePrefix1v6): struct{}{},
						string(bluePoolNodePrefix2v6): struct{}{},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				resource.Key{Name: redPoolName}: RoutePolicyMap{
					redPeer65001v4PodIPPoolRPName: redPeer65001v4PodIPPoolRP,
					redPeer65001v6PodIPPoolRPName: redPeer65001v6PodIPPoolRP,
				},
				resource.Key{Name: bluePoolName}: RoutePolicyMap{
					bluePeer65001v4PodIPPoolRPName: bluePeer65001v4PodIPPoolRP,
					bluePeer65001v6PodIPPoolRPName: bluePeer65001v6PodIPPoolRP,
				},
			},
		},
		{
			name: "dual stack, advertisement selects pools (by nameNS selector), pool present on the node",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvertWithSelector(&redNameNSSelector),
				blueAdvertWithSelector(&blueNameNSSelector),
			},
			pools: []*v2alpha1.CiliumPodIPPool{
				redPool,
				bluePool,
			},
			preconfiguredPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			preconfiguredRPs:         ResourceRoutePolicyMap{},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: metaV1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						Pools: ipamtypes.IPAMPoolSpec{
							Allocated: []ipamtypes.IPAMPoolAllocation{
								{
									Pool: redPoolName,
									CIDRs: []ipamtypes.IPAMPodCIDR{
										redPoolNodePrefix1v4,
										redPoolNodePrefix2v4,
										redPoolNodePrefix1v6,
										redPoolNodePrefix2v6,
									},
								},
								{
									Pool: bluePoolName,
									CIDRs: []ipamtypes.IPAMPodCIDR{
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

			testBGPInstanceConfig: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v2alpha1.CiliumBGPNodePeer{redPeer65001, bluePeer65001},
			},
			expectedPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: redPoolName}: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						string(redPoolNodePrefix1v4): struct{}{},
						string(redPoolNodePrefix2v4): struct{}{},
					},
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						string(redPoolNodePrefix1v6): struct{}{},
						string(redPoolNodePrefix2v6): struct{}{},
					},
				},
				{Name: bluePoolName}: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						string(bluePoolNodePrefix1v4): struct{}{},
						string(bluePoolNodePrefix2v4): struct{}{},
					},
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						string(bluePoolNodePrefix1v6): struct{}{},
						string(bluePoolNodePrefix2v6): struct{}{},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				resource.Key{Name: redPoolName}: RoutePolicyMap{
					redPeer65001v4PodIPPoolRPName: redPeer65001v4PodIPPoolRP,
					redPeer65001v6PodIPPoolRPName: redPeer65001v6PodIPPoolRP,
				},
				resource.Key{Name: bluePoolName}: RoutePolicyMap{
					bluePeer65001v4PodIPPoolRPName: bluePeer65001v4PodIPPoolRP,
					bluePeer65001v6PodIPPoolRPName: bluePeer65001v6PodIPPoolRP,
				},
			},
		},
		{
			name: "dual stack, pool NOT selected by advertisement, pool present on the node",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvert,  // no selector matching red pool
				blueAdvert, // no selector matching blue pool
			},
			pools: []*v2alpha1.CiliumPodIPPool{
				redPool,
				bluePool,
			},
			preconfiguredPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: metaV1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						Pools: ipamtypes.IPAMPoolSpec{
							Allocated: []ipamtypes.IPAMPoolAllocation{
								{
									Pool: redPoolName,
									CIDRs: []ipamtypes.IPAMPodCIDR{
										redPoolNodePrefix1v4,
										redPoolNodePrefix2v4,
										redPoolNodePrefix1v6,
										redPoolNodePrefix2v6,
									},
								},
								{
									Pool: bluePoolName,
									CIDRs: []ipamtypes.IPAMPodCIDR{
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
			testBGPInstanceConfig: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v2alpha1.CiliumBGPNodePeer{redPeer65001, bluePeer65001},
			},
			expectedPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			expectedRPs:         nil,
		},
		{
			name: "dual stack, pool selected by advertisement, pool NOT present on the node",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
				redAdvertWithSelector(&redLabelSelector),
				blueAdvertWithSelector(&blueLabelSelector),
			},
			pools: []*v2alpha1.CiliumPodIPPool{
				redPool,
				bluePool,
			},
			preconfiguredPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: metaV1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						Pools: ipamtypes.IPAMPoolSpec{
							Allocated: []ipamtypes.IPAMPoolAllocation{
								{
									Pool:  redPoolName,
									CIDRs: []ipamtypes.IPAMPodCIDR{},
								},
								{
									Pool:  bluePoolName,
									CIDRs: []ipamtypes.IPAMPodCIDR{},
								},
							},
						},
					},
				},
			},

			testBGPInstanceConfig: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v2alpha1.CiliumBGPNodePeer{redPeer65001, bluePeer65001},
			},
			expectedPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			expectedRPs:         nil,
		},
		{
			name: "dual stack, clean up of preconfigured advertisements",
			peerConfig: []*v2alpha1.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2alpha1.CiliumBGPAdvertisement{
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
			preconfiguredRPs: ResourceRoutePolicyMap{
				resource.Key{Name: redPoolName}: RoutePolicyMap{
					redPeer65001v4PodIPPoolRPName: redPeer65001v4PodIPPoolRP,
					redPeer65001v6PodIPPoolRPName: redPeer65001v6PodIPPoolRP,
				},
				resource.Key{Name: bluePoolName}: RoutePolicyMap{
					bluePeer65001v4PodIPPoolRPName: bluePeer65001v4PodIPPoolRP,
					bluePeer65001v6PodIPPoolRPName: bluePeer65001v6PodIPPoolRP,
				},
			},
			testCiliumNode: &v2api.CiliumNode{
				ObjectMeta: metaV1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2api.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						Pools: ipamtypes.IPAMPoolSpec{
							Allocated: []ipamtypes.IPAMPoolAllocation{
								{
									Pool: redPoolName,
									CIDRs: []ipamtypes.IPAMPodCIDR{
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

			testBGPInstanceConfig: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v2alpha1.CiliumBGPNodePeer{redPeer65001, bluePeer65001},
			},
			expectedPoolAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: redPoolName}: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						string(redPoolNodePrefix1v4): struct{}{},
						string(redPoolNodePrefix2v4): struct{}{},
					},
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						string(redPoolNodePrefix1v6): struct{}{},
						string(redPoolNodePrefix2v6): struct{}{},
					},
				},
			},
			expectedRPs: ResourceRoutePolicyMap{
				resource.Key{Name: redPoolName}: RoutePolicyMap{
					redPeer65001v4PodIPPoolRPName: redPeer65001v4PodIPPoolRP,
					redPeer65001v6PodIPPoolRPName: redPeer65001v6PodIPPoolRP,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			params := PodIPPoolReconcilerIn{
				Logger: podIPPoolTestLogger,
				PeerAdvert: NewCiliumPeerAdvertisement(
					PeerAdvertisementIn{
						Logger:          podCIDRTestLogger,
						PeerConfigStore: store.InitMockStore[*v2alpha1.CiliumBGPPeerConfig](tt.peerConfig),
						AdvertStore:     store.InitMockStore[*v2alpha1.CiliumBGPAdvertisement](tt.advertisements),
					}),
				PoolStore: store.InitMockStore[*v2alpha1.CiliumPodIPPool](tt.pools),
			}
			podIPPoolReconciler := NewPodIPPoolReconciler(params).Reconciler.(*PodIPPoolReconciler)

			testBGPInstance := instance.NewFakeBGPInstance()

			// set the preconfigured advertisements
			presetPoolAFPaths := make(ResourceAFPathsMap)
			for pool, prePoolAFPaths := range tt.preconfiguredPoolAFPaths {
				presetPoolAFPaths[pool] = make(AFPathsMap)
				for fam, afPaths := range prePoolAFPaths {
					pathSet := make(PathMap)
					for prePath := range afPaths {
						path := types.NewPathForPrefix(netip.MustParsePrefix(prePath))
						path.Family = fam
						pathSet[prePath] = path
					}
					presetPoolAFPaths[pool][fam] = pathSet
				}
			}
			podIPPoolReconciler.setMetadata(testBGPInstance, PodIPPoolReconcilerMetadata{
				PoolAFPaths:       presetPoolAFPaths,
				PoolRoutePolicies: tt.preconfiguredRPs,
			})

			// run podIPPoolReconciler twice to ensure idempotency
			for i := 0; i < 2; i++ {
				err := podIPPoolReconciler.Reconcile(context.Background(), ReconcileParams{
					BGPInstance:   testBGPInstance,
					DesiredConfig: tt.testBGPInstanceConfig,
					CiliumNode:    tt.testCiliumNode,
				})
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
			req.Equal(tt.expectedRPs, podIPPoolReconciler.getMetadata(testBGPInstance).PoolRoutePolicies)
		})
	}
}
