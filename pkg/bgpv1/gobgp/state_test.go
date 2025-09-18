// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

var (
	neighbor64125 = &v2alpha1api.CiliumBGPNeighbor{
		PeerASN:                 64125,
		PeerAddress:             "192.168.0.1/32",
		PeerPort:                ptr.To[int32](v2alpha1api.DefaultBGPPeerPort),
		EBGPMultihopTTL:         ptr.To[int32](1),
		ConnectRetryTimeSeconds: ptr.To[int32](99),
		HoldTimeSeconds:         ptr.To[int32](9),
		KeepAliveTimeSeconds:    ptr.To[int32](3),
	}

	// changed ConnectRetryTime
	neighbor64125Update = &v2alpha1api.CiliumBGPNeighbor{
		PeerASN:                 64125,
		PeerAddress:             "192.168.0.1/32",
		PeerPort:                ptr.To[int32](v2alpha1api.DefaultBGPPeerPort),
		EBGPMultihopTTL:         ptr.To[int32](1),
		ConnectRetryTimeSeconds: ptr.To[int32](101),
		HoldTimeSeconds:         ptr.To[int32](9),
		KeepAliveTimeSeconds:    ptr.To[int32](3),
	}

	// enabled graceful restart
	neighbor64125UpdateGR = &v2alpha1api.CiliumBGPNeighbor{
		PeerASN:                 64125,
		PeerAddress:             "192.168.0.1/32",
		PeerPort:                ptr.To[int32](v2alpha1api.DefaultBGPPeerPort),
		EBGPMultihopTTL:         ptr.To[int32](1),
		ConnectRetryTimeSeconds: ptr.To[int32](99),
		HoldTimeSeconds:         ptr.To[int32](9),
		KeepAliveTimeSeconds:    ptr.To[int32](3),
		GracefulRestart: &v2alpha1api.CiliumBGPNeighborGracefulRestart{
			Enabled:            true,
			RestartTimeSeconds: ptr.To[int32](120),
		},
	}

	// enabled graceful restart - updated restart time
	neighbor64125UpdateGRTimer = &v2alpha1api.CiliumBGPNeighbor{
		PeerASN:                 64125,
		PeerAddress:             "192.168.0.1/32",
		PeerPort:                ptr.To[int32](v2alpha1api.DefaultBGPPeerPort),
		EBGPMultihopTTL:         ptr.To[int32](1),
		ConnectRetryTimeSeconds: ptr.To[int32](99),
		HoldTimeSeconds:         ptr.To[int32](9),
		KeepAliveTimeSeconds:    ptr.To[int32](3),
		GracefulRestart: &v2alpha1api.CiliumBGPNeighborGracefulRestart{
			Enabled:            true,
			RestartTimeSeconds: ptr.To[int32](20),
		},
	}

	neighbor64126 = &v2alpha1api.CiliumBGPNeighbor{
		PeerASN:                 64126,
		PeerAddress:             "192.168.66.1/32",
		PeerPort:                ptr.To[int32](v2alpha1api.DefaultBGPPeerPort),
		EBGPMultihopTTL:         ptr.To[int32](1),
		ConnectRetryTimeSeconds: ptr.To[int32](99),
		HoldTimeSeconds:         ptr.To[int32](9),
		KeepAliveTimeSeconds:    ptr.To[int32](3),
	}

	// changed HoldTime & KeepAliveTime
	neighbor64126Update = &v2alpha1api.CiliumBGPNeighbor{
		PeerASN:                 64126,
		PeerAddress:             "192.168.66.1/32",
		PeerPort:                ptr.To[int32](v2alpha1api.DefaultBGPPeerPort),
		EBGPMultihopTTL:         ptr.To[int32](1),
		ConnectRetryTimeSeconds: ptr.To[int32](99),
		HoldTimeSeconds:         ptr.To[int32](12),
		KeepAliveTimeSeconds:    ptr.To[int32](4),
	}

	neighbor64127 = &v2alpha1api.CiliumBGPNeighbor{
		PeerASN:                 64127,
		PeerAddress:             "192.168.88.1/32",
		EBGPMultihopTTL:         ptr.To[int32](1),
		ConnectRetryTimeSeconds: ptr.To[int32](99),
		HoldTimeSeconds:         ptr.To[int32](9),
		KeepAliveTimeSeconds:    ptr.To[int32](3),
	}

	// changed EBGPMultihopTTL
	neighbor64127Update = &v2alpha1api.CiliumBGPNeighbor{
		PeerASN:                 64127,
		PeerAddress:             "192.168.88.1/32",
		EBGPMultihopTTL:         ptr.To[int32](10),
		ConnectRetryTimeSeconds: ptr.To[int32](99),
		HoldTimeSeconds:         ptr.To[int32](9),
		KeepAliveTimeSeconds:    ptr.To[int32](3),
	}

	neighbor64128 = &v2alpha1api.CiliumBGPNeighbor{
		PeerASN:                 64128,
		PeerAddress:             "192.168.77.1/32",
		PeerPort:                ptr.To[int32](v2alpha1api.DefaultBGPPeerPort),
		EBGPMultihopTTL:         ptr.To[int32](1),
		ConnectRetryTimeSeconds: ptr.To[int32](99),
		HoldTimeSeconds:         ptr.To[int32](9),
		KeepAliveTimeSeconds:    ptr.To[int32](3),
	}
)

// TestGetPeerState confirms the parsing of go bgp ListPeers to cilium modes work as intended
func TestGetPeerState(t *testing.T) {
	var table = []struct {
		// name of the test
		name string
		// neighbors to configure
		neighbors []*v2alpha1api.CiliumBGPNeighbor
		// neighbors to update
		neighborsAfterUpdate []*v2alpha1api.CiliumBGPNeighbor
		// localASN is local autonomous number
		localASN uint32
		// expected error message on AddNeighbor() or empty string for no error
		errStr string
		// expected error message  on UpdateNeighbor() or empty string for no error
		updateErrStr string
	}{
		{
			name:      "test add neighbor",
			neighbors: []*v2alpha1api.CiliumBGPNeighbor{neighbor64125},
			localASN:  64124,
			errStr:    "",
		},
		{
			name: "test add neighbor with port",
			neighbors: []*v2alpha1api.CiliumBGPNeighbor{
				{
					PeerASN:                 64125,
					PeerAddress:             "192.168.0.1/32",
					PeerPort:                ptr.To[int32](175),
					ConnectRetryTimeSeconds: ptr.To[int32](99),
					HoldTimeSeconds:         ptr.To[int32](9),
					KeepAliveTimeSeconds:    ptr.To[int32](3),
				},
			},
			localASN: 64124,
			errStr:   "",
		},
		{
			name: "test add + update neighbors",
			neighbors: []*v2alpha1api.CiliumBGPNeighbor{
				neighbor64125,
				neighbor64126,
				neighbor64127,
				neighbor64128,
			},
			neighborsAfterUpdate: []*v2alpha1api.CiliumBGPNeighbor{
				// changed ConnectRetryTime
				neighbor64125Update,
				// changed HoldTime & KeepAliveTime
				neighbor64126Update,
				// changed EBGPMultihopTTL
				neighbor64127Update,
				// no change
				neighbor64128,
			},
			localASN: 64124,
			errStr:   "",
		},
		{
			name: "test graceful restart - update enable",
			neighbors: []*v2alpha1api.CiliumBGPNeighbor{
				neighbor64125,
			},
			neighborsAfterUpdate: []*v2alpha1api.CiliumBGPNeighbor{
				// enabled GR
				neighbor64125UpdateGR,
			},
			localASN: 64124,
			errStr:   "",
		},
		{
			name: "test graceful restart - update restart time",
			neighbors: []*v2alpha1api.CiliumBGPNeighbor{
				neighbor64125UpdateGR,
			},
			neighborsAfterUpdate: []*v2alpha1api.CiliumBGPNeighbor{
				// changed gr restart time
				neighbor64125UpdateGRTimer,
			},
			localASN: 64124,
			errStr:   "",
		},
		{
			name: "test add invalid neighbor",
			neighbors: []*v2alpha1api.CiliumBGPNeighbor{
				// invalid PeerAddress
				{
					PeerASN:                 64125,
					PeerAddress:             "192.168.0.XYZ",
					ConnectRetryTimeSeconds: ptr.To[int32](101),
					HoldTimeSeconds:         ptr.To[int32](30),
					KeepAliveTimeSeconds:    ptr.To[int32](10),
				},
			},
			localASN: 64124,
			errStr:   "failed while adding peer invalid IP with ASN 64125: NeighborAddress is not configured",
		},
		{
			name: "test invalid neighbor update",
			neighbors: []*v2alpha1api.CiliumBGPNeighbor{
				{
					PeerASN:                 64125,
					PeerAddress:             "192.168.0.1/32",
					ConnectRetryTimeSeconds: ptr.To[int32](101),
					HoldTimeSeconds:         ptr.To[int32](30),
					KeepAliveTimeSeconds:    ptr.To[int32](10),
				},
			},
			neighborsAfterUpdate: []*v2alpha1api.CiliumBGPNeighbor{
				// different ASN
				{
					PeerASN:                 64999,
					PeerAddress:             "192.168.0.1/32",
					ConnectRetryTimeSeconds: ptr.To[int32](101),
					HoldTimeSeconds:         ptr.To[int32](30),
					KeepAliveTimeSeconds:    ptr.To[int32](10),
				},
			},
			localASN:     64124,
			errStr:       "",
			updateErrStr: "failed to get existing peer: could not find existing peer with ASN: 64999 and IP: 192.168.0.1",
		},
	}
	for _, tt := range table {
		srvParams := types.ServerParameters{
			Global: types.BGPGlobal{
				ASN:        tt.localASN,
				RouterID:   "127.0.0.1",
				ListenPort: -1,
			},
		}
		t.Run(tt.name, func(t *testing.T) {
			testSC, err := NewGoBGPServer(context.Background(), hivetest.Logger(t), srvParams)
			require.NoError(t, err)

			t.Cleanup(func() {
				testSC.Stop(context.Background(), types.StopRequest{FullDestroy: true})
			})

			// add neighbours
			for _, n := range tt.neighbors {
				n.SetDefaults()

				err = testSC.AddNeighbor(context.Background(), types.ToNeighborV1(n, ""))
				if tt.errStr != "" {
					require.EqualError(t, err, tt.errStr)
					return // no more checks
				} else {
					require.NoError(t, err)
				}
			}

			res, err := testSC.GetPeerState(context.Background())
			require.NoError(t, err)

			// validate neighbors count
			require.Len(t, res.Peers, len(tt.neighbors))

			// validate peers
			validatePeers(t, tt.localASN, tt.neighbors, res.Peers)

			// update neighbours
			for _, n := range tt.neighborsAfterUpdate {
				n.SetDefaults()
				err = testSC.UpdateNeighbor(context.Background(), types.ToNeighborV1(n, ""))
				if tt.updateErrStr != "" {
					require.EqualError(t, err, tt.updateErrStr)
					return // no more checks
				} else {
					require.NoError(t, err)
				}
			}

			res, err = testSC.GetPeerState(context.Background())
			require.NoError(t, err)

			// validate peers
			validatePeers(t, tt.localASN, tt.neighborsAfterUpdate, res.Peers)
		})
	}
}

// validatePeers validates that peers returned from GoBGP GetPeerState match expected list of CiliumBGPNeighbors
func validatePeers(t *testing.T, localASN uint32, neighbors []*v2alpha1api.CiliumBGPNeighbor, peers []*models.BgpPeer) {
	for _, n := range neighbors {
		p := findMatchingPeer(t, peers, n)
		require.NotNilf(t, p, "no matching peer for PeerASN %d and PeerAddress %s", n.PeerASN, n.PeerAddress)

		// validate basic data is returned correctly
		require.Equal(t, int64(localASN), p.LocalAsn)

		expConnectRetry := ptr.Deref[int32](n.ConnectRetryTimeSeconds, v2alpha1api.DefaultBGPConnectRetryTimeSeconds)
		expHoldTime := ptr.Deref[int32](n.HoldTimeSeconds, v2alpha1api.DefaultBGPHoldTimeSeconds)
		expKeepAlive := ptr.Deref[int32](n.KeepAliveTimeSeconds, ptr.Deref[int32](n.KeepAliveTimeSeconds, v2alpha1api.DefaultBGPKeepAliveTimeSeconds))
		require.EqualValues(t, expConnectRetry, p.ConnectRetryTimeSeconds)
		require.EqualValues(t, expHoldTime, p.ConfiguredHoldTimeSeconds)
		require.EqualValues(t, expKeepAlive, p.ConfiguredKeepAliveTimeSeconds)

		if n.GracefulRestart != nil {
			require.Equal(t, n.GracefulRestart.Enabled, p.GracefulRestart.Enabled)
			expGRRestartTime := ptr.Deref[int32](n.GracefulRestart.RestartTimeSeconds, v2alpha1api.DefaultBGPGRRestartTimeSeconds)
			require.EqualValues(t, expGRRestartTime, p.GracefulRestart.RestartTimeSeconds)
		} else {
			require.False(t, p.GracefulRestart.Enabled)
		}

		if n.EBGPMultihopTTL != nil && *n.EBGPMultihopTTL > 0 {
			require.EqualValues(t, *n.EBGPMultihopTTL, p.EbgpMultihopTTL)
		}

		// since there is no real neighbor, bgp session state will be either idle or active.
		require.Contains(t, []string{"idle", "active"}, p.SessionState)
	}
}

// findMatchingPeer finds models.BgpPeer matching to the provided v2alpha1api.CiliumBGPNeighbor based on the peer ASN and IP
func findMatchingPeer(t *testing.T, peers []*models.BgpPeer, n *v2alpha1api.CiliumBGPNeighbor) *models.BgpPeer {
	for _, p := range peers {
		nPrefix, err := netip.ParsePrefix(n.PeerAddress)
		require.NoError(t, err)
		pIP, err := netip.ParseAddr(p.PeerAddress)
		require.NoError(t, err)

		if p.PeerAsn == int64(n.PeerASN) && pIP.Compare(nPrefix.Addr()) == 0 {
			return p
		}
	}
	return nil
}

func TestGetRoutes(t *testing.T) {
	testSC, err := NewGoBGPServer(context.Background(), hivetest.Logger(t), types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        65000,
			RouterID:   "127.0.0.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		testSC.Stop(context.Background(), types.StopRequest{FullDestroy: true})
	})

	err = testSC.AddNeighbor(context.TODO(), types.ToNeighborV1(neighbor64125, ""))
	require.NoError(t, err)

	_, err = testSC.AdvertisePath(context.TODO(), types.PathRequest{
		Path: types.NewPathForPrefix(netip.MustParsePrefix("10.0.0.0/24")),
	})
	require.NoError(t, err)

	_, err = testSC.AdvertisePath(context.TODO(), types.PathRequest{
		Path: types.NewPathForPrefix(netip.MustParsePrefix("fd00::/64")),
	})
	require.NoError(t, err)

	// test IPv4 address family
	res, err := testSC.GetRoutes(context.TODO(), &types.GetRoutesRequest{
		TableType: types.TableTypeLocRIB,
		Family: types.Family{
			Afi:  types.AfiIPv4,
			Safi: types.SafiUnicast,
		},
	})
	require.NoError(t, err)
	require.Len(t, res.Routes, 1)
	require.Len(t, res.Routes[0].Paths, 1)
	require.Equal(t, uint16(bgp.AFI_IP), res.Routes[0].Paths[0].NLRI.AFI())
	require.Equal(t, uint8(bgp.SAFI_UNICAST), res.Routes[0].Paths[0].NLRI.SAFI())
	require.IsType(t, &bgp.IPAddrPrefix{}, res.Routes[0].Paths[0].NLRI)

	// test IPv6 address family
	res, err = testSC.GetRoutes(context.TODO(), &types.GetRoutesRequest{
		TableType: types.TableTypeLocRIB,
		Family: types.Family{
			Afi:  types.AfiIPv6,
			Safi: types.SafiUnicast,
		},
	})
	require.NoError(t, err)
	require.Len(t, res.Routes, 1)
	require.Len(t, res.Routes[0].Paths, 1)
	require.Equal(t, uint16(bgp.AFI_IP6), res.Routes[0].Paths[0].NLRI.AFI())
	require.Equal(t, uint8(bgp.SAFI_UNICAST), res.Routes[0].Paths[0].NLRI.SAFI())
	require.IsType(t, &bgp.IPv6AddrPrefix{}, res.Routes[0].Paths[0].NLRI)

	// test adj-rib-out
	res, err = testSC.GetRoutes(context.TODO(), &types.GetRoutesRequest{
		TableType: types.TableTypeAdjRIBOut,
		Family: types.Family{
			Afi:  types.AfiIPv4,
			Safi: types.SafiUnicast,
		},
		Neighbor: netip.MustParsePrefix(neighbor64125.PeerAddress).Addr(),
	})
	require.NoError(t, err)
	require.Empty(t, res.Routes) // adj-rib is empty as there is no actual peering up

	// test adj-rib-in
	res, err = testSC.GetRoutes(context.TODO(), &types.GetRoutesRequest{
		TableType: types.TableTypeAdjRIBIn,
		Family: types.Family{
			Afi:  types.AfiIPv6,
			Safi: types.SafiUnicast,
		},
		Neighbor: netip.MustParsePrefix(neighbor64125.PeerAddress).Addr(),
	})
	require.NoError(t, err)
	require.Empty(t, res.Routes) // adj-rib is empty as there is no actual peering up
}
