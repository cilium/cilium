// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

func TestNodeReconciler(t *testing.T) {
	cfg := config{Name: "reconciler", RoutingMode: option.RoutingModeTunnel}
	a, ipCache := newTestAgent(
		t.Context(),
		hivetest.Logger(t),
		newFakeWgClient(),
		cfg.toAgentConfig(),
	)
	t.Cleanup(func() { require.NoError(t, ipCache.Shutdown()) })

	n := &node.Node{Node: nodeTypes.Node{
		Name:            k8s1NodeName,
		WireguardPubKey: k8s1PubKey,
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   iputil.AddrFrom(iputil.AddrFromIP(k8s1NodeIPv4)),
		}},
	}}

	local := n.DeepCopy()
	local.Local = &node.LocalNodeInfo{}
	require.NoError(t, a.Update(t.Context(), nil, 1, local))
	require.Empty(t, a.peerByNodeName)

	require.NoError(t, a.Update(t.Context(), nil, 1, n))
	require.Contains(t, a.peerByNodeName, k8s1NodeName)
	require.NoError(t, a.Delete(t.Context(), nil, 2, local))
	require.Contains(t, a.peerByNodeName, k8s1NodeName)

	// Removing the public key means that this node no longer desires a peer.
	n.WireguardPubKey = ""
	require.NoError(t, a.Update(t.Context(), nil, 3, n))
	require.NotContains(t, a.peerByNodeName, k8s1NodeName)

	// Deletes are idempotent, including for nodes that never had a public key.
	require.NoError(t, a.Delete(t.Context(), nil, 4, n))
}

func TestNodeOwnedAllowedIPsIncludeHealthIngressAndPodCIDR(t *testing.T) {
	health6 := netip.MustParseAddr("fd00:10:244:1::9a80")
	ingress6 := netip.MustParseAddr("fd00:10:244:1::6ce6")
	podCIDR := netip.MustParsePrefix("fd00:10:244:1::/64")

	n := &node.Node{Node: nodeTypes.Node{
		Name:            k8s1NodeName,
		WireguardPubKey: k8s1PubKey,
		IPv6HealthIP:    iputil.AddrFrom(health6),
		IPv6IngressIP:   iputil.AddrFrom(ingress6),
		IPv6AllocCIDR:   nodeTypes.PrefixFrom(podCIDR),
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   iputil.AddrFrom(iputil.AddrFromIP(k8s1NodeIPv6)),
		}},
	}}

	got := nodeOwnedAllowedIPs(n)
	require.ElementsMatch(t, []netip.Prefix{
		netip.PrefixFrom(health6, 128),
		netip.PrefixFrom(ingress6, 128),
		podCIDR,
	}, got)
}

func TestNodeReconcilerNativeRoutingAddsHealthAndPodCIDR(t *testing.T) {
	cfg := config{Name: "native-health", RoutingMode: option.RoutingModeNative}
	wgClient := newFakeWgClient()
	a, ipCache := newTestAgent(
		t.Context(),
		hivetest.Logger(t),
		wgClient,
		cfg.toAgentConfig(),
	)
	t.Cleanup(func() { require.NoError(t, ipCache.Shutdown()) })

	health6 := netip.MustParseAddr("fd00:10:244:1::9a80")
	podCIDR := netip.MustParsePrefix("fd00:10:244:1::/64")
	n := &node.Node{Node: nodeTypes.Node{
		Name:            k8s1NodeName,
		WireguardPubKey: k8s1PubKey,
		IPv6HealthIP:    iputil.AddrFrom(health6),
		IPv6AllocCIDR:   nodeTypes.PrefixFrom(podCIDR),
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   iputil.AddrFrom(iputil.AddrFromIP(k8s1NodeIPv6)),
		}},
	}}

	require.NoError(t, a.Update(t.Context(), nil, 1, n))
	peer := a.peerByNodeName[k8s1NodeName]
	require.NotNil(t, peer)

	healthPfx := netip.PrefixFrom(health6, 128)
	require.True(t, peer.hasAllowedIP(healthPfx), "health IP missing from AllowedIPs")
	require.True(t, peer.hasAllowedIP(podCIDR), "pod CIDR missing from AllowedIPs")
	require.True(t, peer.nodeOwnedIPs.Has(healthPfx))
	require.True(t, peer.nodeOwnedIPs.Has(podCIDR))

	// Health IP change should replace the previous node-owned health prefix.
	health6b := netip.MustParseAddr("fd00:10:244:1::abcd")
	n.IPv6HealthIP = iputil.AddrFrom(health6b)
	require.NoError(t, a.Update(t.Context(), nil, 2, n))
	peer = a.peerByNodeName[k8s1NodeName]
	require.False(t, peer.hasAllowedIP(healthPfx), "stale health IP still present")
	require.True(t, peer.hasAllowedIP(netip.PrefixFrom(health6b, 128)))
}
