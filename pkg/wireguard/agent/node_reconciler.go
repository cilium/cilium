// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"iter"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/node"
)

var _ reconciler.Operations[*node.Node] = (*Agent)(nil)

func (a *Agent) Update(
	_ context.Context,
	_ statedb.ReadTxn,
	_ statedb.Revision,
	n *node.Node,
) error {
	if n.Local != nil {
		return nil
	}
	if n.WireguardPubKey == "" {
		return a.deletePeer(n.Fullname())
	}
	return a.updatePeer(n.Fullname(), n.WireguardPubKey, n.GetNodeIP(false), n.GetNodeIP(true))
}

func (a *Agent) Delete(
	_ context.Context,
	_ statedb.ReadTxn,
	_ statedb.Revision,
	n *node.Node,
) error {
	if n.Local != nil {
		return nil
	}
	return a.deletePeer(n.Fullname())
}

// Pruning is handled by peerGarbageCollector after all node and IPCache
// sources have synchronized.
func (a *Agent) Prune(
	context.Context,
	statedb.ReadTxn,
	iter.Seq2[*node.Node, statedb.Revision],
) error {
	return nil
}
