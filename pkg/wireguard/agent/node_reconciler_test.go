// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"errors"
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
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

func TestWaitForNodeReconciliationWaitsForRetries(t *testing.T) {
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)

	n := &node.Node{Node: nodeTypes.Node{Name: "node-1"}}
	n.Statuses = n.Statuses.Set(
		wireGuardNodeReconcilerName,
		reconciler.StatusError(errors.New("injected failure")),
	)
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()

	a := &Agent{
		db:    db,
		nodes: nodes,
	}
	done := make(chan error, 1)
	go func() {
		done <- a.waitForNodeReconciliation(t.Context())
	}()

	select {
	case err := <-done:
		t.Fatalf("returned while reconciliation was failing: %v", err)
	default:
	}

	n = n.DeepCopy()
	n.Statuses = n.Statuses.Set(
		wireGuardNodeReconcilerName,
		reconciler.StatusDone(),
	)
	txn = db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()

	require.NoError(t, <-done)
}
