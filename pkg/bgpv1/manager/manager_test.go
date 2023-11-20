// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/pointer"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

var (
	testSingleIPv4Prefix = []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/24"),
	}
	testSingleIPv6Prefix = []netip.Prefix{
		netip.MustParsePrefix("2001:DB8::/32"),
	}

	testRouterASN         = 64125
	testInvalidRouterASN  = 4126
	testNeighborIP        = "5.6.7.8"
	testInvalidNeighborIP = "1.2.3.4"

	tableTypeLocRib       = "loc-rib"
	tableTypeLocAdjRibOut = "adj-rib-out"
	afiIPv4               = "ipv4"
	afiIPv6               = "ipv6"
	safiUnicast           = "unicast"
)

// TestGetRoutes tests GetRoutes API of the Manager.
func TestGetRoutes(t *testing.T) {

	var table = []struct {
		// name of the test case
		name string

		// advertised prefixes
		advertisedPrefixes []netip.Prefix
		// expected prefixes
		expectedPrefixes []netip.Prefix

		// GetRoutes params
		routerASN *int64
		tableType string
		afi       string
		safi      string
		neighbor  *string

		// non-nil if error is expected, nil if not
		expectedErr error
	}{
		{
			name:               "single IPv4 prefix - retrieve IPv4",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   testSingleIPv4Prefix,
			routerASN:          pointer.Int64(int64(testRouterASN)),
			tableType:          tableTypeLocRib,
			afi:                afiIPv4,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        nil,
		},
		{
			name:               "single IPv4 prefix - retrieve IPv6",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   nil,
			routerASN:          pointer.Int64(int64(testRouterASN)),
			tableType:          tableTypeLocRib,
			afi:                afiIPv6,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        nil,
		},
		{
			name:               "single IPv6 prefix - retrieve IPv6",
			advertisedPrefixes: testSingleIPv6Prefix,
			expectedPrefixes:   testSingleIPv6Prefix,
			routerASN:          nil,
			tableType:          tableTypeLocRib,
			afi:                afiIPv6,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        nil,
		},
		{
			name:               "mixed IPv4 & IPv6 prefixes - retrieve IPv6",
			advertisedPrefixes: []netip.Prefix{testSingleIPv4Prefix[0], testSingleIPv6Prefix[0]},
			routerASN:          nil,
			expectedPrefixes:   testSingleIPv6Prefix,
			tableType:          tableTypeLocRib,
			afi:                afiIPv6,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        nil,
		},
		{
			name:               "incorrect ASN",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   nil,
			routerASN:          pointer.Int64(int64(testInvalidRouterASN)),
			tableType:          tableTypeLocRib,
			afi:                afiIPv4,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        fmt.Errorf(""),
		},
		{
			name:               "missing neighbor for adj-rib-out",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   nil,
			routerASN:          nil,
			tableType:          tableTypeLocAdjRibOut,
			afi:                afiIPv4,
			safi:               safiUnicast,
			neighbor:           nil,
			expectedErr:        fmt.Errorf(""),
		},
		{
			name:               "valid neighbor",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   nil, // nil as the neighbor never goes UP
			routerASN:          nil,
			tableType:          tableTypeLocAdjRibOut,
			afi:                afiIPv4,
			safi:               safiUnicast,
			neighbor:           pointer.String(testNeighborIP),
			expectedErr:        nil,
		},
		{
			name:               "non-existing neighbor",
			advertisedPrefixes: testSingleIPv4Prefix,
			expectedPrefixes:   nil,
			routerASN:          nil,
			tableType:          tableTypeLocAdjRibOut,
			afi:                afiIPv4,
			safi:               safiUnicast,
			neighbor:           pointer.String(testInvalidNeighborIP),
			expectedErr:        fmt.Errorf(""),
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// set up BGPRouterManager with one BGP server
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        uint32(testRouterASN),
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			testSC, err := instance.NewServerWithConfig(context.Background(), log, srvParams)
			require.NoError(t, err)

			testSC.Config = &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:  int64(testRouterASN),
				Neighbors: []v2alpha1api.CiliumBGPNeighbor{},
			}
			brm := &BGPRouterManager{
				Servers: map[int64]*instance.ServerWithConfig{
					int64(testRouterASN): testSC,
				},
			}

			// add a neighbor
			n := &v2alpha1api.CiliumBGPNeighbor{
				PeerAddress: testNeighborIP + "/32",
				PeerASN:     64100,
			}
			n.SetDefaults()
			err = testSC.Server.AddNeighbor(context.Background(), types.NeighborRequest{
				Neighbor: n,
				VR:       testSC.Config,
			})
			require.NoError(t, err)

			// advertise test-provided prefixes
			for _, cidr := range tt.advertisedPrefixes {
				_, err := testSC.Server.AdvertisePath(context.Background(), types.PathRequest{
					Path: types.NewPathForPrefix(cidr),
				})
				require.NoError(t, err)
			}

			// retrieve routes from server's local RIB and
			routes, err := brm.GetRoutes(context.Background(), restapi.GetBgpRoutesParams{
				RouterAsn: tt.routerASN,
				TableType: tt.tableType,
				Afi:       tt.afi,
				Safi:      tt.safi,
				Neighbor:  tt.neighbor,
			})
			if tt.expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}

			// ensure retrieved routes match expected prefixes
			var retrievedPrefixes []netip.Prefix
			for _, r := range routes {
				retrievedPrefixes = append(retrievedPrefixes, netip.MustParsePrefix(r.Prefix))
			}
			require.EqualValues(t, tt.expectedPrefixes, retrievedPrefixes)
		})
	}
}
