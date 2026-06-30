// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	bgpTables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
)

// mustNewIPPrefixes wraps each CIDR string in an ip.Prefix.
func mustNewIPPrefixes(cidrs ...string) []iputil.Prefix {
	prefixes := make([]iputil.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefixes = append(prefixes, iputil.PrefixFrom(netip.MustParsePrefix(cidr)))
	}
	return prefixes
}

// test fixtures
var (
	podCIDR1v4 = "10.10.1.0/24"
	podCIDR1v6 = "2001:db8:1::/96"
	podCIDR2v4 = "10.10.2.0/24"
	podCIDR2v6 = "2001:db8:2::/96"
	podCIDR3v4 = "10.10.3.0/24"
	podCIDR3v6 = "2001:db8:3::/96"

	redPeer65001v4PodCIDRRoutePolicy = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       redPeer65001.Name,
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   PodCIDRReconcilerPriority,
		Owner:      PodCIDRReconcilerName,
		Statement: &types.RoutePolicyStatement{
			Name: PolicyStatementName(v2.BGPPodCIDRAdvert, "") + "-ipv4",
			Conditions: types.RoutePolicyConditions{
				MatchNeighbors: &types.RoutePolicyNeighborMatch{
					Type:      types.RoutePolicyMatchAny,
					Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
				},
				MatchPrefixes: &types.RoutePolicyPrefixMatch{
					Type: types.RoutePolicyMatchAny,
					Prefixes: []types.RoutePolicyPrefix{
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
			},
			Actions: types.RoutePolicyActions{
				RouteAction:    types.RoutePolicyActionAccept,
				AddCommunities: []string{"65000:100"},
			},
		},
	}

	redPeer65001v6PodCIDRRoutePolicy = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       redPeer65001.Name,
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   PodCIDRReconcilerPriority,
		Owner:      PodCIDRReconcilerName,
		Statement: &types.RoutePolicyStatement{
			Name: PolicyStatementName(v2.BGPPodCIDRAdvert, "") + "-ipv6",
			Conditions: types.RoutePolicyConditions{
				MatchNeighbors: &types.RoutePolicyNeighborMatch{
					Type:      types.RoutePolicyMatchAny,
					Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
				},
				MatchPrefixes: &types.RoutePolicyPrefixMatch{
					Type: types.RoutePolicyMatchAny,
					Prefixes: []types.RoutePolicyPrefix{
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
			},
			Actions: types.RoutePolicyActions{
				RouteAction:    types.RoutePolicyActionAccept,
				AddCommunities: []string{"65000:100"},
			},
		},
	}

	bluePeer65001v4PodCIDRRoutePolicy = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       bluePeer65001.Name,
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   PodCIDRReconcilerPriority,
		Owner:      PodCIDRReconcilerName,
		Statement: &types.RoutePolicyStatement{
			Name: PolicyStatementName(v2.BGPPodCIDRAdvert, "") + "-ipv4",
			Conditions: types.RoutePolicyConditions{
				MatchNeighbors: &types.RoutePolicyNeighborMatch{
					Type:      types.RoutePolicyMatchAny,
					Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.2")},
				},
				MatchPrefixes: &types.RoutePolicyPrefixMatch{
					Type: types.RoutePolicyMatchAny,
					Prefixes: []types.RoutePolicyPrefix{
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
			},
			Actions: types.RoutePolicyActions{
				RouteAction:    types.RoutePolicyActionAccept,
				AddCommunities: []string{"65355:100"},
			},
		},
	}

	bluePeer65001v6PodCIDRRoutePolicy = &bgpTables.DesiredRoutePolicy{
		Instance:   "fake-instance",
		Peer:       bluePeer65001.Name,
		PolicyType: types.RoutePolicyTypeExport,
		Priority:   PodCIDRReconcilerPriority,
		Owner:      PodCIDRReconcilerName,
		Statement: &types.RoutePolicyStatement{
			Name: PolicyStatementName(v2.BGPPodCIDRAdvert, "") + "-ipv6",
			Conditions: types.RoutePolicyConditions{
				MatchNeighbors: &types.RoutePolicyNeighborMatch{
					Type:      types.RoutePolicyMatchAny,
					Neighbors: []netip.Addr{netip.MustParseAddr("10.10.10.2")},
				},
				MatchPrefixes: &types.RoutePolicyPrefixMatch{
					Type: types.RoutePolicyMatchAny,
					Prefixes: []types.RoutePolicyPrefix{
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
			},
			Actions: types.RoutePolicyActions{
				RouteAction:    types.RoutePolicyActionAccept,
				AddCommunities: []string{"65355:100"},
			},
		},
	}
)

func Test_PodCIDRAdvertisement(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	tests := []struct {
		name                  string
		peerConfig            []*v2.CiliumBGPPeerConfig
		advertisements        []*v2.CiliumBGPAdvertisement
		preconfiguredPaths    map[types.Family]map[string]struct{}
		preconfiguredRPs      []*bgpTables.DesiredRoutePolicy
		testCiliumNode        *v2.CiliumNode
		testBGPInstanceConfig *v2.CiliumBGPNodeInstance
		expectedPaths         map[types.Family]map[string]struct{}
		expectedRPs           []*bgpTables.DesiredRoutePolicy
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
			preconfiguredRPs:   nil,
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: mustNewIPPrefixes(podCIDR1v4, podCIDR2v4, podCIDR1v6, podCIDR2v6),
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
			expectedRPs: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy,
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
						PodCIDRs: mustNewIPPrefixes(podCIDR1v4, podCIDR2v4, podCIDR1v6, podCIDR2v6),
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
			expectedRPs: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy,
				bluePeer65001v4PodCIDRRoutePolicy,
				bluePeer65001v6PodCIDRRoutePolicy,
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
			preconfiguredRPs: []*bgpTables.DesiredRoutePolicy{
				bluePeer65001v4PodCIDRRoutePolicy,
			},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: mustNewIPPrefixes(podCIDR1v4, podCIDR2v4),
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
			expectedRPs: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy,
			},
		},
		{
			name: "pod cidr advertisement - disable",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
				bluePeerConfig,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				// no pod cidr advertisement configured
				// redPodCIDRAdvert,
				// bluePodCIDRAdvert,
			},
			preconfiguredPaths: map[types.Family]map[string]struct{}{
				// pod cidr 1,2 already advertised, reconcile should clean this as there is no matching pod cidr advertisement.
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					podCIDR1v4: struct{}{},
					podCIDR2v4: struct{}{},
				},
			},
			preconfiguredRPs: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy,
				bluePeer65001v4PodCIDRRoutePolicy,
				bluePeer65001v6PodCIDRRoutePolicy,
			},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: mustNewIPPrefixes(podCIDR1v4, podCIDR2v4),
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
			expectedRPs: nil,
		},
		{
			name: "pod cidr advertisement - v4 only",
			peerConfig: []*v2.CiliumBGPPeerConfig{
				redPeerConfigV4,
			},
			advertisements: []*v2.CiliumBGPAdvertisement{
				redAdvert,
				// bluePodCIDRAdvert,
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
			preconfiguredRPs: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy,
				redPeer65001v6PodCIDRRoutePolicy,
			},
			testCiliumNode: &v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
				},
				Spec: v2.NodeSpec{
					IPAM: ipamtypes.IPAMSpec{
						PodCIDRs: mustNewIPPrefixes(podCIDR1v4, podCIDR2v4),
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
			expectedRPs: []*bgpTables.DesiredRoutePolicy{
				redPeer65001v4PodCIDRRoutePolicy,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			db := statedb.New()
			desiredRoutePolicyTable, err := bgpTables.NewDesiredRoutePoliciesTable(db)
			req.NoError(err)

			// initialize pod cidr reconciler
			p := PodCIDRReconcilerIn{
				Logger: hivetest.Logger(t),
				PeerAdvert: NewCiliumPeerAdvertisement(
					PeerAdvertisementIn{
						Logger:          hivetest.Logger(t),
						PeerConfigStore: store.InitMockStore[*v2.CiliumBGPPeerConfig](tt.peerConfig),
						AdvertStore:     store.InitMockStore[*v2.CiliumBGPAdvertisement](tt.advertisements),
					}),
				DaemonConfig:            &option.DaemonConfig{IPAM: "Kubernetes"},
				DB:                      db,
				DesiredRoutePolicyTable: desiredRoutePolicyTable,
			}
			podCIDRReconciler := NewPodCIDRReconciler(p).Reconciler.(*PodCIDRReconciler)

			// preconfigure advertisements
			testBGPInstance := instance.NewFakeBGPInstance()
			reconcileParams := ReconcileParams{
				BGPInstance:   testBGPInstance,
				DesiredConfig: tt.testBGPInstanceConfig,
				CiliumNode:    tt.testCiliumNode,
			}

			presetAdverts := make(AFPathsMap)
			for preAdvertFam, preAdverts := range tt.preconfiguredPaths {
				pathSet := make(map[string]*types.Path)
				for preAdvert := range preAdverts {
					path := types.MustNewPathForPrefix(netip.MustParsePrefix(preAdvert))
					path.Family = preAdvertFam
					pathSet[preAdvert] = path
				}
				presetAdverts[preAdvertFam] = pathSet
			}
			podCIDRReconciler.setMetadata(testBGPInstance, PodCIDRReconcilerMetadata{
				AFPaths: presetAdverts,
			})

			// set preconfigured policy entries
			tx := db.WriteTxn(podCIDRReconciler.desiredRoutePolicyTable)
			defer tx.Abort()
			for _, policy := range tt.preconfiguredRPs {
				_, _, err := podCIDRReconciler.desiredRoutePolicyTable.Insert(tx, policy)
				require.NoError(t, err)
			}
			tx.Commit()

			// reconcile pod cidr
			// run reconciler twice to ensure idempotency
			for range 2 {
				err := podCIDRReconciler.Reconcile(context.Background(), reconcileParams)
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
			requireDesiredRoutePolicies(t, podCIDRReconciler.db, podCIDRReconciler.desiredRoutePolicyTable,
				testBGPInstance.Name, podCIDRReconciler.Name(), tt.expectedRPs)
		})
	}
}
