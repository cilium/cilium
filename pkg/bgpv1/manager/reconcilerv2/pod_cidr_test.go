// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
)

var (
	podCIDRTestLogger = logrus.WithField("unit_test", "reconcilerv2_podcidr")
)

// test fixtures
var (
	podCIDR1v4 = "10.10.1.0/24"
	podCIDR1v6 = "2001:db8:1::/96"
	podCIDR2v4 = "10.10.2.0/24"
	podCIDR2v6 = "2001:db8:2::/96"
	podCIDR3v4 = "10.10.3.0/24"
	podCIDR3v6 = "2001:db8:3::/96"

	redPeer65001v4PodCIDRRoutePolicy = &types.RoutePolicy{
		Name: "red-peer-65001-ipv4-PodCIDR",
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(podCIDR1v4),
							PrefixLenMin: netip.MustParsePrefix(podCIDR1v4).Bits(),
							PrefixLenMax: netip.MustParsePrefix(podCIDR1v4).Bits(),
						},
						{
							CIDR:         netip.MustParsePrefix(podCIDR2v4),
							PrefixLenMin: netip.MustParsePrefix(podCIDR2v4).Bits(),
							PrefixLenMax: netip.MustParsePrefix(podCIDR2v4).Bits(),
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65000:100"},
				},
			},
		},
	}

	redPeer65001v6PodCIDRRoutePolicy = &types.RoutePolicy{
		Name: "red-peer-65001-ipv6-PodCIDR",
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(podCIDR1v6),
							PrefixLenMin: netip.MustParsePrefix(podCIDR1v6).Bits(),
							PrefixLenMax: netip.MustParsePrefix(podCIDR1v6).Bits(),
						},
						{
							CIDR:         netip.MustParsePrefix(podCIDR2v6),
							PrefixLenMin: netip.MustParsePrefix(podCIDR2v6).Bits(),
							PrefixLenMax: netip.MustParsePrefix(podCIDR2v6).Bits(),
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65000:100"},
				},
			},
		},
	}

	bluePeer65001v4PodCIDRRoutePolicy = &types.RoutePolicy{
		Name: "blue-peer-65001-ipv4-PodCIDR",
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.2/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(podCIDR1v4),
							PrefixLenMin: netip.MustParsePrefix(podCIDR1v4).Bits(),
							PrefixLenMax: netip.MustParsePrefix(podCIDR1v4).Bits(),
						},
						{
							CIDR:         netip.MustParsePrefix(podCIDR2v4),
							PrefixLenMin: netip.MustParsePrefix(podCIDR2v4).Bits(),
							PrefixLenMax: netip.MustParsePrefix(podCIDR2v4).Bits(),
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65355:100"},
				},
			},
		},
	}

	bluePeer65001v6PodCIDRRoutePolicy = &types.RoutePolicy{
		Name: "blue-peer-65001-ipv6-PodCIDR",
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.2/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(podCIDR1v6),
							PrefixLenMin: netip.MustParsePrefix(podCIDR1v6).Bits(),
							PrefixLenMax: netip.MustParsePrefix(podCIDR1v6).Bits(),
						},
						{
							CIDR:         netip.MustParsePrefix(podCIDR2v6),
							PrefixLenMin: netip.MustParsePrefix(podCIDR2v6).Bits(),
							PrefixLenMax: netip.MustParsePrefix(podCIDR2v6).Bits(),
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65355:100"},
				},
			},
		},
	}
)

func Test_PodCIDRAdvertisement(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name                  string
		peerConfig            []*v2.CiliumBGPPeerConfig
		advertisements        []*v2.CiliumBGPAdvertisement
		preconfiguredPaths    map[types.Family]map[string]struct{}
		preconfiguredRPs      RoutePolicyMap
		testCiliumNode        *v2.CiliumNode
		testBGPInstanceConfig *v2.CiliumBGPNodeInstance
		expectedPaths         map[types.Family]map[string]struct{}
		expectedRPs           RoutePolicyMap
	}{
		{
			name: "pod cidr advertisement with no preconfigured advertisements",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			preconfiguredPaths: map[types.Family]map[string]struct{}{},
			preconfiguredRPs:   map[string]*types.RoutePolicy{},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{
							podCIDR1v4,
							podCIDR2v4,
							podCIDR1v6,
							podCIDR2v6,
						},
					},
				},
			},
			testBGPInstanceConfig: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2.CiliumBGPNodePeer{
					redPeer65001,
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					podCIDR1v6: struct{}{},
					podCIDR2v6: struct{}{},
				},
			},
			expectedRPs: map[string]*types.RoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy.Name: redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy.Name: redPeer65001v6PodCIDRRoutePolicy,
			},
		},
		{
			name: "pod cidr advertisement with no preconfigured advertisements - two peers",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			preconfiguredPaths: map[types.Family]map[string]struct{}{},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{
							podCIDR1v4,
							podCIDR2v4,
							podCIDR1v6,
							podCIDR2v6,
						},
					},
				},
			},
			testBGPInstanceConfig: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2.CiliumBGPNodePeer{
					redPeer65001,
					bluePeer65001,
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					podCIDR1v6: struct{}{},
					podCIDR2v6: struct{}{},
				},
			},
			expectedRPs: map[string]*types.RoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy.Name:  redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy.Name:  redPeer65001v6PodCIDRRoutePolicy,
				bluePeer65001v4PodCIDRRoutePolicy.Name: bluePeer65001v4PodCIDRRoutePolicy,
				bluePeer65001v6PodCIDRRoutePolicy.Name: bluePeer65001v6PodCIDRRoutePolicy,
			},
		},
		{
			name: "pod cidr advertisement - cleanup old pod cidr",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvert,
				blueAdvert,
			},
			preconfiguredPaths: map[types.Family]map[string]struct{}{
				// pod cidr 3 is extra advertisement, reconcile should clean this.
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR3v4: struct{}{},
					podCIDR3v6: struct{}{},
				},
			},
			preconfiguredRPs: map[string]*types.RoutePolicy{
				bluePeer65001v4PodCIDRRoutePolicy.Name: bluePeer65001v4PodCIDRRoutePolicy,
			},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1v4, podCIDR2v4},
					},
				},
			},
			testBGPInstanceConfig: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2.CiliumBGPNodePeer{
					redPeer65001,
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {},
			},
			expectedRPs: map[string]*types.RoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy.Name: redPeer65001v4PodCIDRRoutePolicy,
			},
		},
		{
			name: "pod cidr advertisement - disable",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				//no pod cidr advertisement configured
				//redPodCIDRAdvert,
				//bluePodCIDRAdvert,
			},
			preconfiguredPaths: map[types.Family]map[string]struct{}{
				// pod cidr 1,2 already advertised, reconcile should clean this as there is no matching pod cidr advertisement.
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
			},
			preconfiguredRPs: map[string]*types.RoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy.Name:  redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy.Name:  redPeer65001v6PodCIDRRoutePolicy,
				bluePeer65001v4PodCIDRRoutePolicy.Name: bluePeer65001v4PodCIDRRoutePolicy,
				bluePeer65001v6PodCIDRRoutePolicy.Name: bluePeer65001v6PodCIDRRoutePolicy,
			},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1v4, podCIDR2v4},
					},
				},
			},
			testBGPInstanceConfig: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2.CiliumBGPNodePeer{
					redPeer65001,
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {},
			},
			expectedRPs: map[string]*types.RoutePolicy{},
		},
		{
			name: "pod cidr advertisement - v4 only",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfigV4,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvert,
				//bluePodCIDRAdvert,
			},
			preconfiguredPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					podCIDR1v6: struct{}{},
					podCIDR2v6: struct{}{},
				},
			},
			preconfiguredRPs: map[string]*types.RoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy.Name: redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy.Name: redPeer65001v6PodCIDRRoutePolicy,
			},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: []string{podCIDR1v4, podCIDR2v4},
					},
				},
			},
			testBGPInstanceConfig: &v2.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2.CiliumBGPNodePeer{
					{
						Name:        "red-peer-65001",
						PeerAddress: ptr.To[string]("10.10.10.1"),
						PeerConfigRef: &v2.PeerConfigReference{
							Name: "peer-config-red-v4",
						},
					},
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
			},
			expectedRPs: map[string]*types.RoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy.Name: redPeer65001v4PodCIDRRoutePolicy,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			// initialize pod cidr reconciler
			p := PodCIDRReconcilerIn{
				Logger: podCIDRTestLogger,
				PeerAdvert: NewCiliumPeerAdvertisement(
					PeerAdvertisementIn{
						Logger:          podCIDRTestLogger,
						PeerConfigStore: store.InitMockStore[*v2.CiliumBGPPeerConfig](tt.peerConfig),
						AdvertStore:     store.InitMockStore[*v2.CiliumBGPAdvertisement](tt.advertisements),
					}),
				DaemonConfig: &option.DaemonConfig{IPAM: "Kubernetes"},
			}
			podCIDRReconciler := NewPodCIDRReconciler(p).Reconciler.(*PodCIDRReconciler)

			// preconfigure advertisements
			testBGPInstance := instance.NewFakeBGPInstance()

			presetAdverts := make(AFPathsMap)
			for preAdvertFam, preAdverts := range tt.preconfiguredPaths {
				pathSet := make(map[string]*types.Path)
				for preAdvert := range preAdverts {
					path := types.NewPathForPrefix(netip.MustParsePrefix(preAdvert))
					path.Family = preAdvertFam
					pathSet[preAdvert] = path
				}
				presetAdverts[preAdvertFam] = pathSet
			}
			podCIDRReconciler.setMetadata(testBGPInstance, PodCIDRReconcilerMetadata{
				AFPaths:       presetAdverts,
				RoutePolicies: tt.preconfiguredRPs,
			})

			// reconcile pod cidr
			// run reconciler twice to ensure idempotency
			for i := 0; i < 2; i++ {
				err := podCIDRReconciler.Reconcile(context.Background(), ReconcileParams{
					BGPInstance:   testBGPInstance,
					DesiredConfig: tt.testBGPInstanceConfig,
					CiliumNode:    tt.testCiliumNode,
				})
				req.NoError(err)
			}

			// check if the advertisements are as expected
			runningFamilyPaths := make(map[types.Family]map[string]struct{})
			for family, paths := range podCIDRReconciler.getMetadata(testBGPInstance).AFPaths {
				pathSet := make(map[string]struct{})
				for pathKey := range paths {
					pathSet[pathKey] = struct{}{}
				}
				runningFamilyPaths[family] = pathSet
			}

			req.Equal(tt.expectedPaths, runningFamilyPaths)

			// check if the route policies are as expected
			runningRPs := podCIDRReconciler.getMetadata(testBGPInstance).RoutePolicies
			req.Equal(tt.expectedRPs, runningRPs)
		})
	}
}
