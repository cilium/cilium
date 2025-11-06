// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func Test_InterfaceAdvertisement(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	var (
		testCiliumNode = &v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "Test Node",
			},
		}
		testInstanceConfig = &v2.CiliumBGPNodeInstance{
			Name:     "bgp-65001",
			LocalASN: ptr.To[int64](65001),
		}

		redInterfaceName       = "loop-red"
		redInterfaceIPv4Prefix = netip.MustParsePrefix("169.254.1.1/32")
		redInterfaceIPv6Prefix = netip.MustParsePrefix("fd00::aabb:1/128")

		blueInterfaceName       = "loop-blue"
		blueInterfaceIPv4Prefix = netip.MustParsePrefix("10.10.10.100/32")
		blueInterfaceIPv6Prefix = netip.MustParsePrefix("fd00::ccdd:100/128")

		redInterfaceAdvert = &v2.CiliumBGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name: "red-interface-advertisement",
				Labels: map[string]string{
					"advertise": "red_bgp",
				},
			},
			Spec: v2.CiliumBGPAdvertisementSpec{
				Advertisements: []v2.BGPAdvertisement{
					{
						AdvertisementType: v2.BGPInterfaceAdvert,
						Interface: &v2.BGPInterfaceOptions{
							Name: redInterfaceName,
						},
					},
				},
			},
		}
		blueInterfaceAdvert = &v2.CiliumBGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name: "blue-interface-advertisement",
				Labels: map[string]string{
					"advertise": "blue_bgp",
				},
			},
			Spec: v2.CiliumBGPAdvertisementSpec{
				Advertisements: []v2.BGPAdvertisement{
					{
						AdvertisementType: v2.BGPInterfaceAdvert,
						Interface: &v2.BGPInterfaceOptions{
							Name: blueInterfaceName,
						},
					},
				},
			},
		}

		redPeerInterfaceIPv4RoutePolicy = &types.RoutePolicy{
			Name: "red-peer-65001-ipv4-Interface",
			Type: types.RoutePolicyTypeExport,
			Statements: []*types.RoutePolicyStatement{
				{
					Conditions: types.RoutePolicyConditions{
						MatchNeighbors: &types.RoutePolicyNeighborMatch{
							Type:      types.RoutePolicyMatchAny,
							Neighbors: []netip.Addr{netip.MustParseAddr(*redPeer65001.PeerAddress)},
						},
						MatchPrefixes: &types.RoutePolicyPrefixMatch{
							Type: types.RoutePolicyMatchAny,
							Prefixes: []types.RoutePolicyPrefix{
								{
									CIDR:         redInterfaceIPv4Prefix,
									PrefixLenMin: 32,
									PrefixLenMax: 32,
								},
							},
						},
					},
					Actions: types.RoutePolicyActions{
						RouteAction: types.RoutePolicyActionAccept,
					},
				},
			},
		}
		redPeerInterfaceIPv6RoutePolicy = &types.RoutePolicy{
			Name: "red-peer-65001-ipv6-Interface",
			Type: types.RoutePolicyTypeExport,
			Statements: []*types.RoutePolicyStatement{
				{
					Conditions: types.RoutePolicyConditions{
						MatchNeighbors: &types.RoutePolicyNeighborMatch{
							Type:      types.RoutePolicyMatchAny,
							Neighbors: []netip.Addr{netip.MustParseAddr(*redPeer65001.PeerAddress)},
						},
						MatchPrefixes: &types.RoutePolicyPrefixMatch{
							Type: types.RoutePolicyMatchAny,
							Prefixes: []types.RoutePolicyPrefix{
								{
									CIDR:         redInterfaceIPv6Prefix,
									PrefixLenMin: 128,
									PrefixLenMax: 128,
								},
							},
						},
					},
					Actions: types.RoutePolicyActions{
						RouteAction: types.RoutePolicyActionAccept,
					},
				},
			},
		}

		bluePeerInterfaceIPv4RoutePolicy = &types.RoutePolicy{
			Name: "blue-peer-65001-ipv4-Interface",
			Type: types.RoutePolicyTypeExport,
			Statements: []*types.RoutePolicyStatement{
				{
					Conditions: types.RoutePolicyConditions{
						MatchNeighbors: &types.RoutePolicyNeighborMatch{
							Type:      types.RoutePolicyMatchAny,
							Neighbors: []netip.Addr{netip.MustParseAddr(*bluePeer65001.PeerAddress)},
						},
						MatchPrefixes: &types.RoutePolicyPrefixMatch{
							Type: types.RoutePolicyMatchAny,
							Prefixes: []types.RoutePolicyPrefix{
								{
									CIDR:         blueInterfaceIPv4Prefix,
									PrefixLenMin: 32,
									PrefixLenMax: 32,
								},
							},
						},
					},
					Actions: types.RoutePolicyActions{
						RouteAction: types.RoutePolicyActionAccept,
					},
				},
			},
		}
		bluePeerInterfaceIPv6RoutePolicy = &types.RoutePolicy{
			Name: "blue-peer-65001-ipv6-Interface",
			Type: types.RoutePolicyTypeExport,
			Statements: []*types.RoutePolicyStatement{
				{
					Conditions: types.RoutePolicyConditions{
						MatchNeighbors: &types.RoutePolicyNeighborMatch{
							Type:      types.RoutePolicyMatchAny,
							Neighbors: []netip.Addr{netip.MustParseAddr(*bluePeer65001.PeerAddress)},
						},
						MatchPrefixes: &types.RoutePolicyPrefixMatch{
							Type: types.RoutePolicyMatchAny,
							Prefixes: []types.RoutePolicyPrefix{
								{
									CIDR:         blueInterfaceIPv6Prefix,
									PrefixLenMin: 128,
									PrefixLenMax: 128,
								},
							},
						},
					},
					Actions: types.RoutePolicyActions{
						RouteAction: types.RoutePolicyActionAccept,
					},
				},
			},
		}
	)

	tests := []struct {
		name                 string
		peers                []v2.CiliumBGPNodePeer
		upsertPeerConfigs    []*v2.CiliumBGPPeerConfig
		upsertAdvertisements []*v2.CiliumBGPAdvertisement
		upsertDevices        []*tables.Device
		expectedPaths        map[types.Family]map[string]struct{}
		expectedRPs          RoutePolicyMap
	}{
		{
			name: "add red peer - no advertisement",
			peers: []v2.CiliumBGPNodePeer{
				redPeer65001,
			},
			upsertPeerConfigs: []*v2.CiliumBGPPeerConfig{
				redPeerConfig,
			},
			upsertAdvertisements: []*v2.CiliumBGPAdvertisement{
				redInterfaceAdvert,
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {},
			},
			expectedRPs: map[string]*types.RoutePolicy{},
		},
		{
			name: "add red device with IPv4 addr - advertise IPv4",
			peers: []v2.CiliumBGPNodePeer{
				redPeer65001,
			},
			upsertDevices: []*tables.Device{
				{
					Index: 1,
					Name:  redInterfaceName,
					Addrs: []tables.DeviceAddress{
						{Addr: netip.IPv4Unspecified()},          // unspecified should be ignored
						{Addr: netip.MustParseAddr("127.0.0.1")}, // loopback should be ignored
						{Addr: netip.MustParseAddr("224.0.0.1")}, // multicast should be ignored
						{Addr: redInterfaceIPv4Prefix.Addr()},
					},
					Flags:      net.FlagUp,           // admin up
					OperStatus: linkOperStateUnknown, // oper unknown (loopback)
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					redInterfaceIPv4Prefix.String(): struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {},
			},
			expectedRPs: map[string]*types.RoutePolicy{
				redPeerInterfaceIPv4RoutePolicy.Name: redPeerInterfaceIPv4RoutePolicy,
			},
		},
		{
			name: "add IPv6 address to red device - advertise IPv4 + IPv6",
			peers: []v2.CiliumBGPNodePeer{
				redPeer65001,
			},
			upsertDevices: []*tables.Device{
				{
					Index: 1,
					Name:  redInterfaceName,
					Addrs: []tables.DeviceAddress{
						{Addr: redInterfaceIPv4Prefix.Addr()},
						{Addr: netip.IPv6Unspecified()},        // unspecified should be ignored
						{Addr: netip.MustParseAddr("::1")},     // loopback should be ignored
						{Addr: netip.MustParseAddr("ff00::1")}, // multicast should be ignored
						{Addr: netip.MustParseAddr("fe80::1")}, // link-local should be ignored
						{Addr: redInterfaceIPv6Prefix.Addr()},
					},
					Flags:      net.FlagUp,           // admin up
					OperStatus: linkOperStateUnknown, // oper unknown (loopback)
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					redInterfaceIPv4Prefix.String(): struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					redInterfaceIPv6Prefix.String(): struct{}{},
				},
			},
			expectedRPs: map[string]*types.RoutePolicy{
				redPeerInterfaceIPv4RoutePolicy.Name: redPeerInterfaceIPv4RoutePolicy,
				redPeerInterfaceIPv6RoutePolicy.Name: redPeerInterfaceIPv6RoutePolicy,
			},
		},
		{
			name: "add blue interface - no change in advertisements",
			peers: []v2.CiliumBGPNodePeer{
				redPeer65001,
			},
			upsertDevices: []*tables.Device{
				{
					Index: 2,
					Name:  blueInterfaceName,
					Addrs: []tables.DeviceAddress{
						{Addr: blueInterfaceIPv4Prefix.Addr()},
						{Addr: blueInterfaceIPv6Prefix.Addr()},
					},
					Flags:      net.FlagUp,      // admin up
					OperStatus: linkOperStateUp, // oper up
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					redInterfaceIPv4Prefix.String(): struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					redInterfaceIPv6Prefix.String(): struct{}{},
				},
			},
			expectedRPs: map[string]*types.RoutePolicy{
				redPeerInterfaceIPv4RoutePolicy.Name: redPeerInterfaceIPv4RoutePolicy,
				redPeerInterfaceIPv6RoutePolicy.Name: redPeerInterfaceIPv6RoutePolicy,
			},
		},
		{
			name: "add blue peer - advertise red + blue interface addresses",
			peers: []v2.CiliumBGPNodePeer{
				redPeer65001,
				bluePeer65001,
			},
			upsertPeerConfigs: []*v2.CiliumBGPPeerConfig{
				bluePeerConfig,
			},
			upsertAdvertisements: []*v2.CiliumBGPAdvertisement{
				blueInterfaceAdvert,
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					redInterfaceIPv4Prefix.String():  struct{}{},
					blueInterfaceIPv4Prefix.String(): struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					redInterfaceIPv6Prefix.String():  struct{}{},
					blueInterfaceIPv6Prefix.String(): struct{}{},
				},
			},
			expectedRPs: map[string]*types.RoutePolicy{
				redPeerInterfaceIPv4RoutePolicy.Name:  redPeerInterfaceIPv4RoutePolicy,
				redPeerInterfaceIPv6RoutePolicy.Name:  redPeerInterfaceIPv6RoutePolicy,
				bluePeerInterfaceIPv4RoutePolicy.Name: bluePeerInterfaceIPv4RoutePolicy,
				bluePeerInterfaceIPv6RoutePolicy.Name: bluePeerInterfaceIPv6RoutePolicy,
			},
		},
		{
			name: "remove red peer - advertise only blue interface addresses",
			peers: []v2.CiliumBGPNodePeer{
				bluePeer65001,
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
					blueInterfaceIPv4Prefix.String(): struct{}{},
				},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
					blueInterfaceIPv6Prefix.String(): struct{}{},
				},
			},
			expectedRPs: map[string]*types.RoutePolicy{
				bluePeerInterfaceIPv4RoutePolicy.Name: bluePeerInterfaceIPv4RoutePolicy,
				bluePeerInterfaceIPv6RoutePolicy.Name: bluePeerInterfaceIPv6RoutePolicy,
			},
		},
		{
			name: "set blue interface to down - no advertisements",
			peers: []v2.CiliumBGPNodePeer{
				bluePeer65001,
			},
			upsertDevices: []*tables.Device{
				{
					Index: 2,
					Name:  blueInterfaceName,
					Addrs: []tables.DeviceAddress{
						{Addr: blueInterfaceIPv4Prefix.Addr()},
						{Addr: blueInterfaceIPv6Prefix.Addr()},
					},
					Flags:      net.FlagUp, // admin up
					OperStatus: "down",     // oper down
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {},
			},
			expectedRPs: map[string]*types.RoutePolicy{},
		},
		{
			name: "set blue interface to admin down - no advertisements",
			peers: []v2.CiliumBGPNodePeer{
				bluePeer65001,
			},
			upsertDevices: []*tables.Device{
				{
					Index: 2,
					Name:  blueInterfaceName,
					Addrs: []tables.DeviceAddress{
						{Addr: blueInterfaceIPv4Prefix.Addr()},
						{Addr: blueInterfaceIPv6Prefix.Addr()},
					},
					Flags:      0,               // admin down
					OperStatus: linkOperStateUp, // oper up
				},
			},
			expectedPaths: map[types.Family]map[string]struct{}{
				{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {},
				{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {},
			},
			expectedRPs: map[string]*types.RoutePolicy{},
		},
	}

	// initialize test statedb
	req := require.New(t)
	db := statedb.New()
	deviceTable, err := tables.NewDeviceTable(db)
	req.NoError(err)

	// initialize reconciler
	peerConfigStore := store.NewMockBGPCPResourceStore[*v2.CiliumBGPPeerConfig]()
	advertStore := store.NewMockBGPCPResourceStore[*v2.CiliumBGPAdvertisement]()
	p := InterfaceReconcilerIn{
		Logger: hivetest.Logger(t),
		PeerAdvert: NewCiliumPeerAdvertisement(
			PeerAdvertisementIn{
				Logger:          hivetest.Logger(t),
				PeerConfigStore: peerConfigStore,
				AdvertStore:     advertStore,
			},
		),
		DB:          db,
		DeviceTable: deviceTable,
	}
	interfaceReconciler := NewInterfaceReconciler(p).Reconciler.(*InterfaceReconciler)
	testBGPInstance := instance.NewFakeBGPInstance()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// upsert PeerConfigs and advertisements
			for _, pc := range tt.upsertPeerConfigs {
				peerConfigStore.Upsert(pc)
			}
			for _, advert := range tt.upsertAdvertisements {
				advertStore.Upsert(advert)
			}
			// upsert upsertDevices in statedb
			if len(tt.upsertDevices) > 0 {
				wtxn := db.WriteTxn(deviceTable)
				for _, device := range tt.upsertDevices {
					_, _, err = deviceTable.Insert(wtxn, device)
					req.NoError(err)
				}
				wtxn.Commit()
			}

			desiredConfig := testInstanceConfig.DeepCopy()
			desiredConfig.Peers = tt.peers

			// run reconciler twice to ensure idempotency
			for range 2 {
				err := interfaceReconciler.Reconcile(context.Background(), ReconcileParams{
					BGPInstance:   testBGPInstance,
					DesiredConfig: desiredConfig,
					CiliumNode:    testCiliumNode,
				})
				req.NoError(err)
			}

			// check if the advertisements are as expected
			runningFamilyPaths := make(map[types.Family]map[string]struct{})
			for family, paths := range interfaceReconciler.getMetadata(testBGPInstance).AFPaths {
				pathSet := make(map[string]struct{})
				for pathKey := range paths {
					pathSet[pathKey] = struct{}{}
				}
				runningFamilyPaths[family] = pathSet
			}
			req.Equal(tt.expectedPaths, runningFamilyPaths)

			// check if the route policies are as expected
			runningRPs := interfaceReconciler.getMetadata(testBGPInstance).RoutePolicies
			req.Equal(tt.expectedRPs, runningRPs)
		})
	}
}
