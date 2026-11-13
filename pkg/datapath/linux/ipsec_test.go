// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/config"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	ipsecTypes "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type underlayTestAgent struct {
	fakeipsec.Agent
	upserted []*ipsecTypes.Parameters
}

func (a *underlayTestAgent) UpsertIPsecEndpoint(params *ipsecTypes.Parameters) (uint8, error) {
	a.upserted = append(a.upserted, ipsecTypes.NewParameters(params))
	return 1, nil
}

func TestEnableIPSecOverlayUnderlayProtocol(t *testing.T) {
	// Per family: out (one CIDR), fwd and in, plus out and in for the overlay.
	const withoutOverlay, withOverlay = 3, 5

	tests := []struct {
		name           string
		underlay       tunnel.UnderlayProtocol
		wantV4, wantV6 int
	}{
		{"ipv4 underlay", tunnel.IPv4, withOverlay, withoutOverlay},
		{"ipv6 underlay", tunnel.IPv6, withoutOverlay, withOverlay},
		{"unset underlay", "", withOverlay, withOverlay},
	}

	remoteNode := &nodeTypes.Node{
		Name:   "remote-node",
		BootID: "b892866c-26cb-4018-8a55-c0330551a2be",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeInternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("192.0.2.2"))},
			{Type: addressing.NodeInternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("fd00::2"))},
			{Type: addressing.NodeCiliumInternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.2"))},
			{Type: addressing.NodeCiliumInternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("fd01::2"))},
		},
		IPv4AllocCIDR: nodeTypes.PrefixFrom(netip.MustParsePrefix("10.1.0.0/24")),
		IPv6AllocCIDR: nodeTypes.PrefixFrom(netip.MustParsePrefix("fd02::/96")),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := &underlayTestAgent{}
			handler := newNodeHandler(
				hivetest.Logger(t),
				DatapathConfiguration{UnderlayProtocol: tt.underlay},
				nil, kpr.KPRConfig{}, agent, fakeipsec.Config{},
				node.NewTestLocalNodeStore(node.LocalNode{}), newNodePolicy(), nil, nil, nil,
			)
			handler.nodeConfig = config.Config{
				EnableIPv4:          true,
				EnableIPv6:          true,
				EnableIPSec:         true,
				EnableEncapsulation: true,
				NodeIPv4:            netip.MustParseAddr("192.0.2.1"),
				NodeIPv6:            netip.MustParseAddr("fd00::1"),
				CiliumInternalIPv4:  netip.MustParseAddr("10.0.0.1"),
				CiliumInternalIPv6:  netip.MustParseAddr("fd01::1"),
			}

			// Using the same node as old and new leaves no added or removed
			// CIDRs, so no routes are touched.
			_, err := handler.enableIPSecIPv4Do(remoteNode, remoteNode, 0x1234, false, nil)
			require.NoError(t, err)
			require.Len(t, agent.upserted, tt.wantV4)

			agent.upserted = nil
			_, err = handler.enableIPSecIPv6Do(remoteNode, remoteNode, 0x1234, false, nil)
			require.NoError(t, err)
			require.Len(t, agent.upserted, tt.wantV6)
		})
	}
}
