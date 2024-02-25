// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

var (
	defaultConf = neighborConf{
		address: "1.2.3.4",
		port:    ptr.To[int32](179),
		asn:     65001,
	}

	invalidIPConf = neighborConf{
		address: "1.2.3.x",
		port:    ptr.To[int32](179),
		asn:     65001,
	}

	afiConf = func() neighborConf {
		d := defaultConf.DeepCopy()
		d.families = []v2alpha1.CiliumBGPFamily{
			{
				Afi:  "l2vpn",
				Safi: "multicast",
			},
		}
		return d
	}

	invalidAfiConf = func() neighborConf {
		d := defaultConf.DeepCopy()
		d.families = []v2alpha1.CiliumBGPFamily{
			{
				Afi:  "foo",
				Safi: "bar",
			},
		}
		return d
	}

	multiHopConf = func() neighborConf {
		d := defaultConf.DeepCopy()
		d.multihop = ptr.To[int32](3)
		return d
	}

	timersConf = func() neighborConf {
		d := defaultConf.DeepCopy()
		d.timers = &timersConfig{
			connect:   60,
			hold:      30,
			keepalive: 15,
		}
		return d
	}

	restartConf = func() neighborConf {
		d := defaultConf.DeepCopy()
		d.restart = &restartConfig{
			enabled: true,
			time:    ptr.To[int32](90),
		}
		return d
	}
)

type restartConfig struct {
	enabled bool
	time    *int32
}

type timersConfig struct {
	connect   int32
	hold      int32
	keepalive int32
}

type neighborConf struct {
	address  string
	port     *int32
	asn      int64
	families []v2alpha1.CiliumBGPFamily
	multihop *int32
	timers   *timersConfig
	restart  *restartConfig
}

func (n neighborConf) DeepCopy() neighborConf {
	neighCopy := neighborConf{
		address:  n.address,
		port:     ptr.To[int32](*n.port),
		asn:      n.asn,
		multihop: n.multihop,
	}

	neighCopy.families = make([]v2alpha1.CiliumBGPFamily, len(n.families))
	for i, f := range n.families {
		neighCopy.families[i] = *f.DeepCopy()
	}

	if n.timers != nil {
		neighCopy.timers = &timersConfig{
			connect:   n.timers.connect,
			hold:      n.timers.hold,
			keepalive: n.timers.keepalive,
		}
	}

	if n.restart != nil {
		neighCopy.restart = &restartConfig{
			enabled: n.restart.enabled,
			time:    ptr.To[int32](*n.restart.time),
		}
	}

	return neighCopy
}

func neighborFromTestConf(c neighborConf) *v2alpha1.CiliumBGPNeighbor {
	n := &v2alpha1.CiliumBGPNeighbor{
		PeerAddress:              fmt.Sprintf("%s/32", c.address),
		PeerPort:                 ptr.To[int32](179),
		PeerASN:                  c.asn,
		EBGPMultihopTTL:          c.multihop,
		GracefulRestart:          &v2alpha1.CiliumBGPNeighborGracefulRestart{},
		Families:                 c.families,
		AdvertisedPathAttributes: []v2alpha1.CiliumBGPPathAttributes{},
		ConnectRetryTimeSeconds:  ptr.To[int32](120),
		HoldTimeSeconds:          ptr.To[int32](90),
		KeepAliveTimeSeconds:     ptr.To[int32](30),
	}

	if c.port != nil {
		n.PeerPort = c.port
	}

	if c.timers != nil {
		n.ConnectRetryTimeSeconds = &c.timers.connect
		n.HoldTimeSeconds = &c.timers.hold
		n.KeepAliveTimeSeconds = &c.timers.keepalive
	}

	if c.restart != nil {
		n.GracefulRestart.Enabled = c.restart.enabled
		n.GracefulRestart.RestartTimeSeconds = c.restart.time
	}

	return n
}

func bgpNodePeerFromTestConf(c neighborConf) *v2alpha1.CiliumBGPNodePeer {
	p := &v2alpha1.CiliumBGPNodePeer{
		Name:        "peer-1",
		PeerAddress: ptr.To[string](c.address),
		PeerASN:     ptr.To[int64](c.asn),
	}

	return p
}

func bgpPeerConfigFromTestConf(c neighborConf) *v2alpha1.CiliumBGPPeerConfigSpec {
	p := &v2alpha1.CiliumBGPPeerConfigSpec{}
	p.SetDefaults()

	p.Families = []v2alpha1.CiliumBGPFamilyWithAdverts{}
	for _, fam := range c.families {
		p.Families = append(p.Families, v2alpha1.CiliumBGPFamilyWithAdverts{
			CiliumBGPFamily: fam,
		})
	}

	if c.multihop != nil {
		p.EBGPMultihop = c.multihop
	}

	if c.port != nil {
		p.Transport.PeerPort = c.port
	}

	if c.timers != nil {
		p.Timers.ConnectRetryTimeSeconds = &c.timers.connect
		p.Timers.HoldTimeSeconds = &c.timers.hold
		p.Timers.KeepAliveTimeSeconds = &c.timers.keepalive
	}

	if c.restart != nil {
		p.GracefulRestart.Enabled = c.restart.enabled
		p.GracefulRestart.RestartTimeSeconds = c.restart.time
	}

	return p
}

func gobgpPeerFromTestConf(c neighborConf) *gobgp.Peer {
	p := &gobgp.Peer{
		Conf: &gobgp.PeerConf{
			NeighborAddress: c.address,
			PeerAsn:         uint32(c.asn),
		},
		Transport: &gobgp.Transport{
			RemotePort: uint32(*c.port),
		},
		Timers:          &gobgp.Timers{},
		GracefulRestart: &gobgp.GracefulRestart{},
	}

	addr, err := netip.ParseAddr(c.address)
	if err != nil {
		return nil
	}
	if addr.Is4() {
		p.Transport.LocalAddress = wildcardIPv4Addr
	} else {
		p.Transport.LocalAddress = wildcardIPv6Addr
	}

	p.AfiSafis, err = convertBGPNeighborSAFI(c.families)
	if err != nil {
		return nil
	}

	if testServerParameters.Global.ASN != uint32(c.asn) && c.multihop != nil && *c.multihop > 1 {
		p.EbgpMultihop = &gobgp.EbgpMultihop{
			Enabled:     true,
			MultihopTtl: uint32(*c.multihop),
		}
	}

	if c.timers != nil {
		p.Timers.Config = &gobgp.TimersConfig{
			ConnectRetry:      uint64(c.timers.connect),
			HoldTime:          uint64(c.timers.hold),
			KeepaliveInterval: uint64(c.timers.keepalive),
		}
	} else {
		p.Timers.Config = &gobgp.TimersConfig{
			ConnectRetry:      uint64(120),
			HoldTime:          uint64(90),
			KeepaliveInterval: uint64(30),
		}
	}
	p.Timers.Config.IdleHoldTimeAfterReset = idleHoldTimeAfterResetSeconds

	if c.restart != nil {
		p.GracefulRestart.Enabled = true
		p.GracefulRestart.NotificationEnabled = true
		if c.restart.time != nil {
			p.GracefulRestart.RestartTime = uint32(*c.restart.time)
		} else {
			p.GracefulRestart.RestartTime = uint32(120)
		}
	}

	return p
}

func TestGetPeerConfigV1(t *testing.T) {
	table := []struct {
		name     string
		neighbor *v2alpha1.CiliumBGPNeighbor
		expected *gobgp.Peer
		expect   bool
	}{
		{
			name:     "test nil neighbor",
			neighbor: nil,
			expected: nil,
			expect:   false,
		},
		{
			name:     "test default neighbor config",
			neighbor: neighborFromTestConf(defaultConf),
			expected: gobgpPeerFromTestConf(defaultConf),
			expect:   true,
		},
		{
			name:     "test default invalid IP neighbor config",
			neighbor: neighborFromTestConf(invalidIPConf),
			expected: gobgpPeerFromTestConf(invalidIPConf),
			expect:   false,
		},
		{
			name:     "test neighbor afi safi config",
			neighbor: neighborFromTestConf(afiConf()),
			expected: gobgpPeerFromTestConf(afiConf()),
			expect:   true,
		},
		{
			name:     "test neighbor invalid afi safi config",
			neighbor: neighborFromTestConf(invalidAfiConf()),
			expected: gobgpPeerFromTestConf(invalidAfiConf()),
			expect:   false,
		},
		{
			name:     "test neighbor ebgp multihop ttl config",
			neighbor: neighborFromTestConf(multiHopConf()),
			expected: gobgpPeerFromTestConf(multiHopConf()),
			expect:   true,
		},
		{
			name:     "test neighbor ebgp multihop timers config",
			neighbor: neighborFromTestConf(timersConf()),
			expected: gobgpPeerFromTestConf(timersConf()),
			expect:   true,
		},
		{
			name:     "test neighbor graceful restart timers config",
			neighbor: neighborFromTestConf(restartConf()),
			expected: gobgpPeerFromTestConf(restartConf()),
			expect:   true,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			svr, err := NewGoBGPServer(context.Background(), log, testServerParameters)
			require.NoError(t, err)

			t.Cleanup(func() {
				svr.Stop()
			})

			req := types.NeighborRequest{
				Neighbor: tt.neighbor,
			}

			peer, reset, err := svr.(*GoBGPServer).getPeerConfig(context.Background(), req, false)
			if tt.expect {
				require.NoError(t, err)
				require.Equal(t, tt.expected.Conf, peer.Conf)
				require.Equal(t, tt.expected.Transport, peer.Transport)
				require.Equal(t, tt.expected.Timers, peer.Timers)
				require.Equal(t, tt.expected.EbgpMultihop, peer.EbgpMultihop)
				require.Equal(t, reset, false)
				if len(tt.expected.AfiSafis) > 0 {
					for i, safi := range tt.expected.AfiSafis {
						require.Equal(t, safi.Config, peer.AfiSafis[i].Config)
					}
				}
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestGetPeerConfigV2(t *testing.T) {
	table := []struct {
		name       string
		peer       *v2alpha1.CiliumBGPNodePeer
		peerConfig *v2alpha1.CiliumBGPPeerConfigSpec
		expected   *gobgp.Peer
		expect     bool
	}{
		{
			name:       "test nil peer and config",
			peer:       nil,
			peerConfig: nil,
			expected:   nil,
			expect:     false,
		},
		{
			name:       "test default neighbor config",
			peer:       bgpNodePeerFromTestConf(defaultConf),
			peerConfig: bgpPeerConfigFromTestConf(defaultConf),
			expected:   gobgpPeerFromTestConf(defaultConf),
			expect:     true,
		},
		{
			name:       "test default invalid IP neighbor config",
			peer:       bgpNodePeerFromTestConf(invalidIPConf),
			peerConfig: bgpPeerConfigFromTestConf(invalidIPConf),
			expected:   gobgpPeerFromTestConf(invalidIPConf),
			expect:     false,
		},
		{
			name:       "test neighbor afi safi config",
			peer:       bgpNodePeerFromTestConf(afiConf()),
			peerConfig: bgpPeerConfigFromTestConf(afiConf()),
			expected:   gobgpPeerFromTestConf(afiConf()),
			expect:     true,
		},
		{
			name:       "test neighbor invalid afi safi config",
			peer:       bgpNodePeerFromTestConf(invalidAfiConf()),
			peerConfig: bgpPeerConfigFromTestConf(invalidAfiConf()),
			expected:   gobgpPeerFromTestConf(invalidAfiConf()),
			expect:     false,
		},
		{
			name:       "test neighbor ebgp multihop ttl config",
			peer:       bgpNodePeerFromTestConf(multiHopConf()),
			peerConfig: bgpPeerConfigFromTestConf(multiHopConf()),
			expected:   gobgpPeerFromTestConf(multiHopConf()),
			expect:     true,
		},
		{
			name:       "test neighbor ebgp multihop timers config",
			peer:       bgpNodePeerFromTestConf(timersConf()),
			peerConfig: bgpPeerConfigFromTestConf(timersConf()),
			expected:   gobgpPeerFromTestConf(timersConf()),
			expect:     true,
		},
		{
			name:       "test neighbor graceful restart timers config",
			peer:       bgpNodePeerFromTestConf(restartConf()),
			peerConfig: bgpPeerConfigFromTestConf(restartConf()),
			expected:   gobgpPeerFromTestConf(restartConf()),
			expect:     true,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			svr, err := NewGoBGPServer(context.Background(), log, testServerParameters)
			require.NoError(t, err)

			t.Cleanup(func() {
				svr.Stop()
			})

			req := types.NeighborRequest{
				Peer:       tt.peer,
				PeerConfig: tt.peerConfig,
			}

			peer, reset, err := svr.(*GoBGPServer).getPeerConfig(context.Background(), req, false)
			if tt.expect {
				require.NoError(t, err)
				require.Equal(t, tt.expected.Conf, peer.Conf)
				require.Equal(t, tt.expected.Transport, peer.Transport)
				require.Equal(t, tt.expected.Timers, peer.Timers)
				require.Equal(t, tt.expected.EbgpMultihop, peer.EbgpMultihop)
				require.Equal(t, reset, false)
				if len(tt.expected.AfiSafis) > 0 {
					for i, safi := range tt.expected.AfiSafis {
						require.Equal(t, safi.Config, peer.AfiSafis[i].Config)
					}
				}
			} else {
				require.Error(t, err)
			}
		})
	}
}
