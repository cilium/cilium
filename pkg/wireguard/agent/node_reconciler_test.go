// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

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
			IP:   net.IP(k8s1NodeIPv4),
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
