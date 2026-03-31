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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgp/types"
)

var (
	neighbor64125 = &types.Neighbor{
		Name:    "neighbor-64125",
		ASN:     64125,
		Address: netip.MustParseAddr("192.168.0.1"),
		Transport: &types.NeighborTransport{
			RemotePort: 179,
		},
		EbgpMultihop: &types.NeighborEbgpMultihop{
			TTL: 1,
		},
		Timers: &types.NeighborTimers{
			ConnectRetry:      99,
			HoldTime:          9,
			KeepaliveInterval: 3,
		},
	}

	// changed ConnectRetryTime
	neighbor64125Update = &types.Neighbor{
		Name:    "neighbor-64125",
		ASN:     64125,
		Address: netip.MustParseAddr("192.168.0.1"),
		Transport: &types.NeighborTransport{
			RemotePort: 179,
		},
		EbgpMultihop: &types.NeighborEbgpMultihop{
			TTL: 1,
		},
		Timers: &types.NeighborTimers{
			ConnectRetry:      101,
			HoldTime:          9,
			KeepaliveInterval: 3,
		},
	}

	// enabled graceful restart
	neighbor64125UpdateGR = &types.Neighbor{
		Name:    "neighbor-64125",
		ASN:     64125,
		Address: netip.MustParseAddr("192.168.0.1"),
		Transport: &types.NeighborTransport{
			RemotePort: 179,
		},
		EbgpMultihop: &types.NeighborEbgpMultihop{
			TTL: 1,
		},
		Timers: &types.NeighborTimers{
			ConnectRetry:      99,
			HoldTime:          9,
			KeepaliveInterval: 3,
		},
		GracefulRestart: &types.NeighborGracefulRestart{
			Enabled:     true,
			RestartTime: 120,
		},
	}

	// enabled graceful restart - updated restart time
	neighbor64125UpdateGRTimer = &types.Neighbor{
		Name:    "neighbor-64125",
		ASN:     64125,
		Address: netip.MustParseAddr("192.168.0.1"),
		Transport: &types.NeighborTransport{
			RemotePort: 179,
		},
		EbgpMultihop: &types.NeighborEbgpMultihop{
			TTL: 1,
		},
		Timers: &types.NeighborTimers{
			ConnectRetry:      99,
			HoldTime:          9,
			KeepaliveInterval: 3,
		},
		GracefulRestart: &types.NeighborGracefulRestart{
			Enabled:     true,
			RestartTime: 20,
		},
	}

	neighbor64126 = &types.Neighbor{
		Name:    "neighbor-64126",
		ASN:     64126,
		Address: netip.MustParseAddr("192.168.66.1"),
		Transport: &types.NeighborTransport{
			RemotePort: 179,
		},
		EbgpMultihop: &types.NeighborEbgpMultihop{
			TTL: 1,
		},
		Timers: &types.NeighborTimers{
			ConnectRetry:      99,
			HoldTime:          9,
			KeepaliveInterval: 3,
		},
	}

	// changed HoldTime & KeepAliveTime
	neighbor64126Update = &types.Neighbor{
		Name:    "neighbor-64126",
		ASN:     64126,
		Address: netip.MustParseAddr("192.168.66.1"),
		Transport: &types.NeighborTransport{
			RemotePort: 179,
		},
		EbgpMultihop: &types.NeighborEbgpMultihop{
			TTL: 1,
		},
		Timers: &types.NeighborTimers{
			ConnectRetry:      99,
			HoldTime:          12,
			KeepaliveInterval: 4,
		},
	}

	neighbor64127 = &types.Neighbor{
		Name:    "neighbor-64127",
		ASN:     64127,
		Address: netip.MustParseAddr("192.168.88.1"),
		EbgpMultihop: &types.NeighborEbgpMultihop{
			TTL: 1,
		},
		Timers: &types.NeighborTimers{
			ConnectRetry:      99,
			HoldTime:          9,
			KeepaliveInterval: 3,
		},
	}

	// changed EBGPMultihopTTL
	neighbor64127Update = &types.Neighbor{
		Name:    "neighbor-64127",
		ASN:     64127,
		Address: netip.MustParseAddr("192.168.88.1"),
		EbgpMultihop: &types.NeighborEbgpMultihop{
			TTL: 10,
		},
		Timers: &types.NeighborTimers{
			ConnectRetry:      99,
			HoldTime:          9,
			KeepaliveInterval: 3,
		},
	}

	neighbor64128 = &types.Neighbor{
		Name:    "neighbor-64128",
		ASN:     64128,
		Address: netip.MustParseAddr("192.168.77.1"),
		Transport: &types.NeighborTransport{
			RemotePort: 179,
		},
		EbgpMultihop: &types.NeighborEbgpMultihop{
			TTL: 1,
		},
		Timers: &types.NeighborTimers{
			ConnectRetry:      99,
			HoldTime:          9,
			KeepaliveInterval: 3,
		},
	}
)

// TestGetPeerState confirms the parsing of go bgp ListPeers to cilium modes work as intended
func TestGetPeerState(t *testing.T) {
	var table = []struct {
		// name of the test
		name string
		// neighbors to configure
		neighbors []*types.Neighbor
		// neighbors to update
		neighborsAfterUpdate []*types.Neighbor
		// localASN is local autonomous number
		localASN uint32
		// expected error message on AddNeighbor() or empty string for no error
		errStr string
		// expected error message  on UpdateNeighbor() or empty string for no error
		updateErrStr string
	}{
		{
			name:      "test add neighbor",
			neighbors: []*types.Neighbor{neighbor64125},
			localASN:  64124,
			errStr:    "",
		},
		{
			name: "test add neighbor with port",
			neighbors: []*types.Neighbor{
				{
					ASN:     64125,
					Address: netip.MustParseAddr("192.168.0.1"),
					Transport: &types.NeighborTransport{
						RemotePort: 175,
					},
					Timers: &types.NeighborTimers{
						ConnectRetry:      99,
						HoldTime:          9,
						KeepaliveInterval: 3,
					},
				},
			},
			localASN: 64124,
			errStr:   "",
		},
		{
			name: "test add + update neighbors",
			neighbors: []*types.Neighbor{
				neighbor64125,
				neighbor64126,
				neighbor64127,
				neighbor64128,
			},
			neighborsAfterUpdate: []*types.Neighbor{
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
			neighbors: []*types.Neighbor{
				neighbor64125,
			},
			neighborsAfterUpdate: []*types.Neighbor{
				// enabled GR
				neighbor64125UpdateGR,
			},
			localASN: 64124,
			errStr:   "",
		},
		{
			name: "test graceful restart - update restart time",
			neighbors: []*types.Neighbor{
				neighbor64125UpdateGR,
			},
			neighborsAfterUpdate: []*types.Neighbor{
				// changed gr restart time
				neighbor64125UpdateGRTimer,
			},
			localASN: 64124,
			errStr:   "",
		},
		{
			name: "test invalid neighbor update",
			neighbors: []*types.Neighbor{
				{
					ASN:     64125,
					Address: netip.MustParseAddr("192.168.0.1"),
					Timers: &types.NeighborTimers{
						ConnectRetry:      101,
						HoldTime:          30,
						KeepaliveInterval: 10,
					},
				},
			},
			neighborsAfterUpdate: []*types.Neighbor{
				// different ASN
				{
					ASN:     64999,
					Address: netip.MustParseAddr("192.168.0.1"),
					Timers: &types.NeighborTimers{
						ConnectRetry:      101,
						HoldTime:          30,
						KeepaliveInterval: 10,
					},
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
				err = testSC.AddNeighbor(context.Background(), n)
				if tt.errStr != "" {
					require.EqualError(t, err, tt.errStr)
					return // no more checks
				} else {
					require.NoError(t, err)
				}
			}

			res, err := testSC.GetPeerStateLegacy(context.Background())
			require.NoError(t, err)

			// validate neighbors count
			require.Len(t, res.Peers, len(tt.neighbors))

			// validate peers
			validatePeers(t, tt.localASN, tt.neighbors, res.Peers)

			// update neighbours
			for _, n := range tt.neighborsAfterUpdate {
				err = testSC.UpdateNeighbor(context.Background(), n)
				if tt.updateErrStr != "" {
					require.EqualError(t, err, tt.updateErrStr)
					return // no more checks
				} else {
					require.NoError(t, err)
				}
			}

			res, err = testSC.GetPeerStateLegacy(context.Background())
			require.NoError(t, err)

			// validate peers
			validatePeers(t, tt.localASN, tt.neighborsAfterUpdate, res.Peers)
		})
	}
}

// validatePeers validates that peers returned from GoBGP GetPeerState match expected list of CiliumBGPNeighbors
func validatePeers(t *testing.T, localASN uint32, neighbors []*types.Neighbor, peers []*models.BgpPeer) {
	for _, n := range neighbors {
		p := findMatchingPeer(peers, n)
		require.NotNilf(t, p, "no matching peer for PeerASN %d and PeerAddress %s", n.ASN, n.Address.String())

		// validate basic data is returned correctly
		require.Equal(t, int64(localASN), p.LocalAsn)

		expConnectRetry := n.Timers.ConnectRetry
		expHoldTime := n.Timers.HoldTime
		expKeepAlive := n.Timers.KeepaliveInterval
		require.EqualValues(t, expConnectRetry, p.ConnectRetryTimeSeconds)
		require.EqualValues(t, expHoldTime, p.ConfiguredHoldTimeSeconds)
		require.EqualValues(t, expKeepAlive, p.ConfiguredKeepAliveTimeSeconds)

		if n.GracefulRestart != nil {
			require.Equal(t, n.GracefulRestart.Enabled, p.GracefulRestart.Enabled)
			expGRRestartTime := n.GracefulRestart.RestartTime
			require.EqualValues(t, expGRRestartTime, p.GracefulRestart.RestartTimeSeconds)
		} else {
			require.False(t, p.GracefulRestart.Enabled)
		}

		if n.EbgpMultihop != nil && n.EbgpMultihop.TTL > 0 {
			require.EqualValues(t, n.EbgpMultihop.TTL, p.EbgpMultihopTTL)
		}

		// since there is no real neighbor, bgp session state will be either idle or active.
		require.Contains(t, []string{"idle", "active"}, p.SessionState)
	}
}

// findMatchingPeer finds models.BgpPeer matching to the provided types.Neighbor based on the name
func findMatchingPeer(peers []*models.BgpPeer, n *types.Neighbor) *models.BgpPeer {
	for _, p := range peers {
		if p.Name == n.Name {
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

	err = testSC.AddNeighbor(context.TODO(), neighbor64125)
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
		Neighbor: neighbor64125.Address,
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
		Neighbor: neighbor64125.Address,
	})
	require.NoError(t, err)
	require.Empty(t, res.Routes) // adj-rib is empty as there is no actual peering up
}
