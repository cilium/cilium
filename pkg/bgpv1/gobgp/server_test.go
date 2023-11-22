// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

var testServerParameters = types.ServerParameters{
	Global: types.BGPGlobal{
		ASN:        65000,
		RouterID:   "127.0.0.1",
		ListenPort: -1,
	},
}

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

func neighborFromConf(c neighborConf) *v2alpha1.CiliumBGPNeighbor {
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

func peerFromConf(c neighborConf) *gobgp.Peer {
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

func TestGetPeerConfig(t *testing.T) {
	defaultConf := neighborConf{
		address: "1.2.3.4",
		port:    ptr.To[int32](179),
		asn:     65001,
	}

	invalidIPConf := neighborConf{
		address: "1.2.3.x",
		port:    ptr.To[int32](179),
		asn:     65001,
	}

	afiConf := defaultConf
	afiConf.families = []v2alpha1.CiliumBGPFamily{
		{
			Afi:  "l2vpn",
			Safi: "multicast",
		},
	}

	invalidAfiConf := defaultConf
	invalidAfiConf.families = []v2alpha1.CiliumBGPFamily{
		{
			Afi:  "foo",
			Safi: "bar",
		},
	}

	multiHopConf := defaultConf
	multiHopConf.multihop = ptr.To[int32](3)

	timersConf := defaultConf
	timersConf.timers = &timersConfig{
		connect:   60,
		hold:      30,
		keepalive: 15,
	}

	restartConf := defaultConf
	restartConf.restart = &restartConfig{
		enabled: true,
		time:    ptr.To[int32](90),
	}

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
			neighbor: neighborFromConf(defaultConf),
			expected: peerFromConf(defaultConf),
			expect:   true,
		},
		{
			name:     "test default invalid IP neighbor config",
			neighbor: neighborFromConf(invalidIPConf),
			expected: peerFromConf(invalidIPConf),
			expect:   false,
		},
		{
			name:     "test neighbor afi safi config",
			neighbor: neighborFromConf(afiConf),
			expected: peerFromConf(afiConf),
			expect:   true,
		},
		{
			name:     "test neighbor invalid afi safi config",
			neighbor: neighborFromConf(invalidAfiConf),
			expected: peerFromConf(invalidAfiConf),
			expect:   false,
		},
		{
			name:     "test neighbor ebgp multihop ttl config",
			neighbor: neighborFromConf(multiHopConf),
			expected: peerFromConf(multiHopConf),
			expect:   true,
		},
		{
			name:     "test neighbor ebgp multihop timers config",
			neighbor: neighborFromConf(timersConf),
			expected: peerFromConf(timersConf),
			expect:   true,
		},
		{
			name:     "test neighbor graceful restart timers config",
			neighbor: neighborFromConf(restartConf),
			expected: peerFromConf(restartConf),
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

			router := &v2alpha1.CiliumBGPVirtualRouter{
				LocalASN:  int64(testServerParameters.Global.ASN),
				Neighbors: []v2alpha1.CiliumBGPNeighbor{},
			}

			req := types.NeighborRequest{
				Neighbor: tt.neighbor,
				VR:       router,
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

func TestAddRemoveRoutePolicy(t *testing.T) {
	for _, tt := range types.TestCommonRoutePolicies {
		t.Run(tt.Name, func(t *testing.T) {
			router, err := NewGoBGPServer(context.Background(), log, testServerParameters)
			require.NoError(t, err)

			t.Cleanup(func() {
				router.Stop()
			})
			gobgpServer := router.(*GoBGPServer).server

			// add testing policy
			err = router.AddRoutePolicy(context.Background(), types.RoutePolicyRequest{Policy: tt.Policy})
			if !tt.Valid {
				// if error is expected, check that polices are cleaned up and return
				require.Error(t, err)
				checkPoliciesCleanedUp(t, gobgpServer)
				return
			}
			require.NoError(t, err)

			// retrieve policies
			pResp, err := router.GetRoutePolicies(context.Background())
			require.NoError(t, err)

			// check that retrieved policy matches the expected
			require.Len(t, pResp.Policies, 1)
			require.EqualValues(t, tt.Policy, pResp.Policies[0])

			// remove testing policy
			err = router.RemoveRoutePolicy(context.Background(), types.RoutePolicyRequest{Policy: tt.Policy})
			require.NoError(t, err)

			checkPoliciesCleanedUp(t, gobgpServer)
		})
	}
}

func checkPoliciesCleanedUp(t *testing.T, gobgpServer *server.BgpServer) {
	// check that polies were removed
	cnt := 0
	err := gobgpServer.ListPolicy(context.Background(), &gobgp.ListPolicyRequest{}, func(p *gobgp.Policy) {
		cnt++
	})
	require.NoError(t, err)
	require.Equal(t, 0, cnt, "leaked policies")

	// check that policy assignments were removed
	cnt = 0
	err = gobgpServer.ListPolicyAssignment(context.Background(), &gobgp.ListPolicyAssignmentRequest{}, func(a *gobgp.PolicyAssignment) {
		cnt += len(a.Policies)
	})
	require.NoError(t, err)
	require.Equal(t, 0, cnt, "leaked policy assignments")

	// check that defined sets were removed
	cnt = 0
	err = gobgpServer.ListDefinedSet(context.Background(), &gobgp.ListDefinedSetRequest{}, func(ds *gobgp.DefinedSet) {
		cnt++
	})
	require.NoError(t, err)
	require.Equal(t, 0, cnt, "leaked policy defined sets")
}
