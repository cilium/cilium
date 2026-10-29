// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"bytes"
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
			neighbor := ToNeighborV2(tt.nodePeer, tt.peerConfig, tt.authPassword, nil)
			require.Equal(t, tt.expected, neighbor)
		})
	}
}

func TestToNeighborV2TCPAO(t *testing.T) {
	tcpAO := &NeighborTCPAO{
		SendID: 1,
		Keys: []TCPAOKey{
			{SendID: 1, ReceiveID: 1, Algorithm: TCPAOAlgorithmHMACSHA1_96, MasterKey: []byte("secret")},
		},
	}
	neighbor := ToNeighborV2(
		&v2.CiliumBGPNodePeer{Name: "peer", PeerAddress: ptr.To("10.0.0.1"), PeerASN: ptr.To(int64(65001))},
		&v2.CiliumBGPPeerConfigSpec{},
		"",
		tcpAO,
	)
	require.Same(t, tcpAO, neighbor.TCPAO)
	require.Empty(t, neighbor.AuthPassword)
}

func TestToNeighborTCPAOV2(t *testing.T) {
	validSecret := map[string][]byte{
		"key-1":  []byte("master-key-1"),
		"key-2":  []byte("master-key-2"),
		"custom": []byte("master-key-custom"),
	}

	var table = []struct {
		name     string
		apiTCPAO *v2.CiliumBGPTCPAO
		secret   map[string][]byte
		expected *NeighborTCPAO
		errStr   string
	}{
		{
			name:     "nil config",
			apiTCPAO: nil,
			secret:   validSecret,
			expected: nil,
		},
		{
			name: "single key with defaults",
			apiTCPAO: &v2.CiliumBGPTCPAO{
				SecretRef: "secret",
				Keys: []v2.CiliumBGPTCPAOKey{
					{SendID: 1, ReceiveID: 1},
				},
			},
			secret: validSecret,
			expected: &NeighborTCPAO{
				SendID: 1,
				Keys: []TCPAOKey{
					{SendID: 1, ReceiveID: 1, Algorithm: TCPAOAlgorithmHMACSHA1_96, MasterKey: []byte("master-key-1")},
				},
			},
		},
		{
			name: "multiple keys, explicit send key, algorithms and secret keys",
			apiTCPAO: &v2.CiliumBGPTCPAO{
				SecretRef: "secret",
				SendKeyID: ptr.To(int32(2)),
				Keys: []v2.CiliumBGPTCPAOKey{
					{SendID: 1, ReceiveID: 11, Algorithm: v2.BGPTCPAOAlgorithmAES128CMAC_96},
					{SendID: 2, ReceiveID: 12, Algorithm: v2.BGPTCPAOAlgorithmHMACSHA256_128, ExcludeTCPOptions: true, SecretKey: "custom"},
				},
			},
			secret: validSecret,
			expected: &NeighborTCPAO{
				SendID: 2,
				Keys: []TCPAOKey{
					{SendID: 1, ReceiveID: 11, Algorithm: TCPAOAlgorithmAES128CMAC_96, MasterKey: []byte("master-key-1")},
					{SendID: 2, ReceiveID: 12, Algorithm: TCPAOAlgorithmHMACSHA256_128, ExcludeTCPOptions: true, MasterKey: []byte("master-key-custom")},
				},
			},
		},
		{
			name: "default send key is the lowest send ID",
			apiTCPAO: &v2.CiliumBGPTCPAO{
				SecretRef: "secret",
				Keys: []v2.CiliumBGPTCPAOKey{
					{SendID: 2, ReceiveID: 2},
					{SendID: 1, ReceiveID: 1},
				},
			},
			secret: validSecret,
			expected: &NeighborTCPAO{
				SendID: 1,
				Keys: []TCPAOKey{
					{SendID: 2, ReceiveID: 2, Algorithm: TCPAOAlgorithmHMACSHA1_96, MasterKey: []byte("master-key-2")},
					{SendID: 1, ReceiveID: 1, Algorithm: TCPAOAlgorithmHMACSHA1_96, MasterKey: []byte("master-key-1")},
				},
			},
		},
		{
			name: "missing master key in secret",
			apiTCPAO: &v2.CiliumBGPTCPAO{
				SecretRef: "secret",
				Keys: []v2.CiliumBGPTCPAOKey{
					{SendID: 1, ReceiveID: 1},
					{SendID: 3, ReceiveID: 3},
				},
			},
			secret: validSecret,
			errStr: "TCP-AO master key missing in the secret: key \"key-3\" (TCP-AO send ID 3)",
		},
		{
			name: "master key too long",
			apiTCPAO: &v2.CiliumBGPTCPAO{
				SecretRef: "secret",
				Keys: []v2.CiliumBGPTCPAOKey{
					{SendID: 1, ReceiveID: 1},
				},
			},
			secret: map[string][]byte{"key-1": bytes.Repeat([]byte("a"), TCPAOMaxMasterKeyLen+1)},
			errStr: "TCP-AO key with send ID 1 must have a master key of 1 - 80 bytes",
		},
		{
			name: "unknown algorithm",
			apiTCPAO: &v2.CiliumBGPTCPAO{
				SecretRef: "secret",
				Keys: []v2.CiliumBGPTCPAOKey{
					{SendID: 1, ReceiveID: 1, Algorithm: "md5"},
				},
			},
			secret: validSecret,
			errStr: "TCP-AO key with send ID 1 has an unsupported algorithm \"md5\"",
		},
		{
			name: "send key ID not in the keychain",
			apiTCPAO: &v2.CiliumBGPTCPAO{
				SecretRef: "secret",
				SendKeyID: ptr.To(int32(5)),
				Keys: []v2.CiliumBGPTCPAOKey{
					{SendID: 1, ReceiveID: 1},
				},
			},
			secret: validSecret,
			errStr: "TCP-AO send ID 5 does not match any key of the keychain",
		},
		{
			name: "duplicate receive ID",
			apiTCPAO: &v2.CiliumBGPTCPAO{
				SecretRef: "secret",
				Keys: []v2.CiliumBGPTCPAOKey{
					{SendID: 1, ReceiveID: 1},
					{SendID: 2, ReceiveID: 1},
				},
			},
			secret: validSecret,
			errStr: "duplicate TCP-AO receive ID 1",
		},
		{
			name: "send ID out of range",
			apiTCPAO: &v2.CiliumBGPTCPAO{
				SecretRef: "secret",
				Keys: []v2.CiliumBGPTCPAOKey{
					{SendID: 256, ReceiveID: 1},
				},
			},
			secret: validSecret,
			errStr: "TCP-AO send ID 256 is outside 0..255",
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			tcpAO, err := ToNeighborTCPAOV2(tt.apiTCPAO, tt.secret)
			if tt.errStr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errStr)
				require.Nil(t, tcpAO)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, tcpAO)
			if tcpAO != nil {
				// master keys must be copies, not aliases of the secret data
				for _, k := range tcpAO.Keys {
					for _, v := range tt.secret {
						if len(v) > 0 && len(k.MasterKey) > 0 {
							require.NotSame(t, &v[0], &k.MasterKey[0])
						}
					}
				}
			}
		})
	}
}
