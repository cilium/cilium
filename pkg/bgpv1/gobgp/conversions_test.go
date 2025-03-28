// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"net/netip"
	"testing"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgpv1/types"
)

// Test common Path type conversions appearing in the codebase
func TestPathConversions(t *testing.T) {
	for _, tt := range types.CommonPaths {
		t.Run(tt.Name, func(t *testing.T) {
			s := server.NewBgpServer()
			go s.Serve()

			err := s.StartBgp(context.TODO(), &gobgp.StartBgpRequest{
				Global: &gobgp.Global{
					Asn:        65000,
					RouterId:   "127.0.0.1",
					ListenPort: -1,
				},
			})
			require.NoError(t, err)

			t.Cleanup(func() {
				s.Stop()
			})

			path, err := ToGoBGPPath(&tt.Path)
			require.NoError(t, err)

			res, err := s.AddPath(context.TODO(), &gobgp.AddPathRequest{
				Path: path,
			})
			require.NoError(t, err)
			require.NotZero(t, res.Uuid)

			req := &gobgp.ListPathRequest{
				Family: path.Family,
			}
			err = s.ListPath(context.TODO(), req, func(destination *gobgp.Destination) {
				paths, err := ToAgentPaths(destination.Paths)
				require.NoError(t, err)
				require.NotZero(t, paths)
				require.Equal(t, tt.Path.NLRI, paths[0].NLRI)
				require.Len(t, paths[0].PathAttributes, len(tt.Path.PathAttributes))
				for i := range tt.Path.PathAttributes {
					// byte-compare encoded path attributes
					data1, err := tt.Path.PathAttributes[i].Serialize()
					require.NoError(t, err)
					data2, err := paths[0].PathAttributes[i].Serialize()
					require.NoError(t, err)
					require.Equal(t, data1, data2)
				}
			})
			require.NoError(t, err)
		})
	}
}

func TestToGoBGPPeer(t *testing.T) {
	tests := []struct {
		name     string
		neighbor *types.Neighbor
		expected *gobgp.Peer
	}{
		{
			name: "Address IPv4",
			neighbor: &types.Neighbor{
				Address: netip.MustParseAddr("10.0.0.1"),
			},
			expected: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "10.0.0.1",
				},
				AfiSafis: defaultSafiAfi,
			},
		},
		{
			name: "Address IPv6",
			neighbor: &types.Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
			},
			expected: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "fd00::1",
				},
				AfiSafis: defaultSafiAfi,
			},
		},
		{
			name: "ASN",
			neighbor: &types.Neighbor{
				Address: netip.MustParseAddr("10.0.0.1"),
				ASN:     65000,
			},
			expected: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "10.0.0.1",
					PeerAsn:         65000,
				},
				AfiSafis: defaultSafiAfi,
			},
		},
		{
			name: "AuthPassword",
			neighbor: &types.Neighbor{
				Address:      netip.MustParseAddr("10.0.0.1"),
				AuthPassword: "password",
			},
			expected: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "10.0.0.1",
					AuthPassword:    "password",
				},
				AfiSafis: defaultSafiAfi,
			},
		},
		{
			name: "EbgpMultihop",
			neighbor: &types.Neighbor{
				Address: netip.MustParseAddr("10.0.0.1"),
				EbgpMultihop: &types.NeighborEbgpMultihop{
					TTL: 10,
				},
			},
			expected: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "10.0.0.1",
				},
				EbgpMultihop: &gobgp.EbgpMultihop{
					Enabled:     true,
					MultihopTtl: 10,
				},
				AfiSafis: defaultSafiAfi,
			},
		},
		{
			name: "RouteReflector",
			neighbor: &types.Neighbor{
				Address: netip.MustParseAddr("10.0.0.1"),
				RouteReflector: &types.NeighborRouteReflector{
					Client:    true,
					ClusterID: "255.0.0.1",
				},
			},
			expected: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "10.0.0.1",
				},
				RouteReflector: &gobgp.RouteReflector{
					RouteReflectorClient:    true,
					RouteReflectorClusterId: "255.0.0.1",
				},
				AfiSafis: defaultSafiAfi,
			},
		},
		{
			name: "Timers",
			neighbor: &types.Neighbor{
				Address: netip.MustParseAddr("10.0.0.1"),
				Timers: &types.NeighborTimers{
					ConnectRetry:      10,
					HoldTime:          30,
					KeepaliveInterval: 10,
				},
			},
			expected: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "10.0.0.1",
				},
				Timers: &gobgp.Timers{
					Config: &gobgp.TimersConfig{
						ConnectRetry:           10,
						HoldTime:               30,
						KeepaliveInterval:      10,
						IdleHoldTimeAfterReset: idleHoldTimeAfterResetSeconds,
					},
				},
				AfiSafis: defaultSafiAfi,
			},
		},
		{
			name: "Transport",
			neighbor: &types.Neighbor{
				Address: netip.MustParseAddr("10.0.0.1"),
				Transport: &types.NeighborTransport{
					LocalAddress: "10.0.0.2",
					LocalPort:    1179,
					RemotePort:   1179,
				},
			},
			expected: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "10.0.0.1",
				},
				Transport: &gobgp.Transport{
					LocalAddress: "10.0.0.2",
					LocalPort:    1179,
					RemotePort:   1179,
				},
				AfiSafis: defaultSafiAfi,
			},
		},
		{
			name: "GracefulRestart",
			neighbor: &types.Neighbor{
				Address: netip.MustParseAddr("10.0.0.1"),
				GracefulRestart: &types.NeighborGracefulRestart{
					Enabled:     true,
					RestartTime: 100,
				},
				AfiSafis: []*types.Family{
					{
						Afi:  types.AfiIPv4,
						Safi: types.SafiUnicast,
					},
				},
			},
			expected: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "10.0.0.1",
				},
				GracefulRestart: &gobgp.GracefulRestart{
					Enabled:             true,
					RestartTime:         100,
					NotificationEnabled: true,
					LocalRestarting:     true,
				},
				AfiSafis: []*gobgp.AfiSafi{
					{
						Config: &gobgp.AfiSafiConfig{
							Family: GoBGPIPv4Family,
						},
						MpGracefulRestart: &gobgp.MpGracefulRestart{
							Config: &gobgp.MpGracefulRestartConfig{
								Enabled: true,
							},
						},
					},
				},
			},
		},
		{
			name: "AfiSafis",
			neighbor: &types.Neighbor{
				Address: netip.MustParseAddr("10.0.0.1"),
				AfiSafis: []*types.Family{
					{
						Afi:  types.AfiIPv6,
						Safi: types.SafiUnicast,
					},
				},
			},
			expected: &gobgp.Peer{
				Conf: &gobgp.PeerConf{
					NeighborAddress: "10.0.0.1",
				},
				AfiSafis: []*gobgp.AfiSafi{
					{
						Config: &gobgp.AfiSafiConfig{
							Family: GoBGPIPv6Family,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := ToGoBGPPeer(tt.neighbor, nil, tt.neighbor.Address.Is4())
			require.Equal(t, tt.expected, actual)
		})
	}
}
