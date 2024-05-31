// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"iter"
	"log/slog"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

var NodeReconcilerCell = cell.Module(
	"node-reconciler",
	"Datapath Node reconciler",

	cell.Invoke(registerNodeReconciler),
)

type nodeReconcilerParams struct {
	cell.In

	Log              *slog.Logger
	Table            statedb.RWTable[node.Node]
	Handler          datapath.NodeHandler
	ReconcilerParams reconciler.Params
}

func registerNodeReconciler(p nodeReconcilerParams) error {
	// Name of the reconciler
	const name = "linux"

	ops := &proxyOps{p.Log, p.Handler, make(map[string]node.Node)}
	_, err := reconciler.Register(
		p.ReconcilerParams,
		p.Table,
		node.Node.Clone,
		func(n node.Node, s reconciler.Status) node.Node {
			return n.SetReconciliationStatus(name, s)
		},
		func(n node.Node) reconciler.Status {
			return n.GetReconciliationStatus(name)
		},
		ops,
		nil,
	)
	return err
}

type proxyOps struct {
	log      *slog.Logger
	handler  datapath.NodeHandler
	previous map[string]node.Node
}

// Delete implements reconciler.Operations.
func (m *proxyOps) Delete(ctx context.Context, txn statedb.ReadTxn, node node.Node) error {
	return m.handler.NodeDelete(node.GetNode())
}

// Prune implements reconciler.Operations.
func (m *proxyOps) Prune(context.Context, statedb.ReadTxn, iter.Seq2[node.Node, statedb.Revision]) error {
	return nil
}

// Update implements reconciler.Operations.
func (m *proxyOps) Update(ctx context.Context, txn statedb.ReadTxn, node node.Node) error {
	old, hadOld := m.previous[node.Name()]
	m.previous[node.Name()] = node

	if hadOld {
		return m.handler.NodeUpdate(node.GetNode(), old.GetNode())
	}
	return m.handler.NodeAdd(node.GetNode())
}

var _ reconciler.Operations[node.Node] = &proxyOps{}
