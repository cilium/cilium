// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestToNeighbor(t *testing.T) {
	table := []struct {
		name         string
		nodePeer     *v2.CiliumBGPNodePeer
		peerConfig   *v2.CiliumBGPPeerConfigSpec
		authPassword string
		expected     *Neighbor
	}{
		{
			name: "IPv4 Minimal",
			nodePeer: &v2.CiliumBGPNodePeer{
				PeerAddress: ptr.To("10.0.0.1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v2.CiliumBGPPeerConfigSpec{},
			expected: &Neighbor{
				Address: netip.MustParseAddr("10.0.0.1"),
				ASN:     64512,
			},
		},
		{
			name: "IPv6 Minimal",
			nodePeer: &v2.CiliumBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v2.CiliumBGPPeerConfigSpec{},
			expected: &Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
			},
		},
		{
			name: "LocalAddress",
			nodePeer: &v2.CiliumBGPNodePeer{
				PeerAddress:  ptr.To("fd00::1"),
				PeerASN:      ptr.To(int64(64512)),
				LocalAddress: ptr.To("fd00::2"),
			},
			peerConfig: &v2.CiliumBGPPeerConfigSpec{},
			expected: &Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				Transport: &NeighborTransport{
					LocalAddress: "fd00::2",
				},
			},
		},
		{
			name: "PeerPort",
			nodePeer: &v2.CiliumBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v2.CiliumBGPPeerConfigSpec{
				Transport: &v2.CiliumBGPTransport{
					PeerPort: ptr.To(int32(1790)),
				},
			},
			expected: &Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				Transport: &NeighborTransport{
					RemotePort: 1790,
				},
			},
		},
		{
			name: "Timers",
			nodePeer: &v2.CiliumBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v2.CiliumBGPPeerConfigSpec{
				Timers: &v2.CiliumBGPTimers{
					ConnectRetryTimeSeconds: ptr.To(int32(1)),
					HoldTimeSeconds:         ptr.To(int32(3)),
					KeepAliveTimeSeconds:    ptr.To(int32(1)),
				},
			},
			expected: &Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				Timers: &NeighborTimers{
					ConnectRetry:      1,
					HoldTime:          3,
					KeepaliveInterval: 1,
				},
			},
		},
		{
			name: "AuthPassword",
			nodePeer: &v2.CiliumBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig:   &v2.CiliumBGPPeerConfigSpec{},
			authPassword: "password",
			expected: &Neighbor{
				Address:      netip.MustParseAddr("fd00::1"),
				ASN:          64512,
				AuthPassword: "password",
			},
		},
		{
			name: "GracefulRestart",
			nodePeer: &v2.CiliumBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v2.CiliumBGPPeerConfigSpec{
				GracefulRestart: &v2.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: ptr.To(int32(3)),
				},
			},
			expected: &Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				GracefulRestart: &NeighborGracefulRestart{
					Enabled:     true,
					RestartTime: 3,
				},
			},
		},
		{
			name: "EBGPMultihop",
			nodePeer: &v2.CiliumBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v2.CiliumBGPPeerConfigSpec{
				EBGPMultihop: ptr.To(int32(3)),
			},
			expected: &Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				EbgpMultihop: &NeighborEbgpMultihop{
					TTL: 3,
				},
			},
		},
		{
			name: "Families",
			nodePeer: &v2.CiliumBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},

			peerConfig: &v2.CiliumBGPPeerConfigSpec{
				Families: []v2.CiliumBGPFamilyWithAdverts{
					{

						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv4",
							Safi: "unicast",
						},
					},
					{
						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv6",
							Safi: "unicast",
						},
					},
				},
			},
			expected: &Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				AfiSafis: []*Family{
					{
						Afi:  AfiIPv4,
						Safi: SafiUnicast,
					},
					{
						Afi:  AfiIPv6,
						Safi: SafiUnicast,
					},
				},
			},
		},
		{
			name: "Maximum",
			nodePeer: &v2.CiliumBGPNodePeer{
				PeerAddress:  ptr.To("fd00::1"),
				PeerASN:      ptr.To(int64(64512)),
				LocalAddress: ptr.To("fd00::2"),
			},
			peerConfig: &v2.CiliumBGPPeerConfigSpec{
				Transport: &v2.CiliumBGPTransport{
					PeerPort: ptr.To(int32(1790)),
				},
				Timers: &v2.CiliumBGPTimers{
					ConnectRetryTimeSeconds: ptr.To(int32(1)),
					HoldTimeSeconds:         ptr.To(int32(3)),
					KeepAliveTimeSeconds:    ptr.To(int32(1)),
				},
				GracefulRestart: &v2.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: ptr.To(int32(3)),
				},
				EBGPMultihop: ptr.To(int32(3)),
				Families: []v2.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv4",
							Safi: "unicast",
						},
					},
					{
						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv6",
							Safi: "unicast",
						},
					},
				},
			},
			authPassword: "password",
			expected: &Neighbor{
				Address:      netip.MustParseAddr("fd00::1"),
				ASN:          64512,
				AuthPassword: "password",
				EbgpMultihop: &NeighborEbgpMultihop{
					TTL: 3,
				},
				Timers: &NeighborTimers{
					ConnectRetry:      1,
					HoldTime:          3,
					KeepaliveInterval: 1,
				},
				Transport: &NeighborTransport{
					LocalAddress: "fd00::2",
					RemotePort:   1790,
				},
				GracefulRestart: &NeighborGracefulRestart{
					Enabled:     true,
					RestartTime: 3,
				},
				AfiSafis: []*Family{
					{
						Afi:  AfiIPv4,
						Safi: SafiUnicast,
					},
					{
						Afi:  AfiIPv6,
						Safi: SafiUnicast,
					},
				},
			},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			neighbor := ToNeighborV2(tt.nodePeer, tt.peerConfig, tt.authPassword)
			require.Equal(t, tt.expected, neighbor)
		})
	}
}
