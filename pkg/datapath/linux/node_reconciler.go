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
	Table            statedb.RWTable[*node.TableNode]
	Handler          datapath.NodeHandler
	ReconcilerParams reconciler.Params
}

func registerNodeReconciler(p nodeReconcilerParams) error {
	// Name of the reconciler
	const name = "linux"

	ops := &proxyOps{p.Log, p.Handler, make(map[string]*node.TableNode)}
	_, err := reconciler.Register(
		p.ReconcilerParams,
		p.Table,
		(*node.TableNode).Clone,
		func(n *node.TableNode, s reconciler.Status) *node.TableNode {
			n.Statuses = n.Statuses.Set(name, s)
			return n
		},
		func(n *node.TableNode) reconciler.Status {
			return n.Statuses.Get(name)
		},
		ops,
		nil,
	)
	return err
}

type proxyOps struct {
	log      *slog.Logger
	handler  datapath.NodeHandler
	previous map[string]*node.TableNode
}

// Delete implements reconciler.Operations.
func (m *proxyOps) Delete(ctx context.Context, txn statedb.ReadTxn, node *node.TableNode) error {
	return m.handler.NodeDelete(node.Node)
}

// Prune implements reconciler.Operations.
func (m *proxyOps) Prune(context.Context, statedb.ReadTxn, iter.Seq2[*node.TableNode, statedb.Revision]) error {
	return nil
}

// Update implements reconciler.Operations.
func (m *proxyOps) Update(ctx context.Context, txn statedb.ReadTxn, node *node.TableNode) error {
	old, hadOld := m.previous[node.Name]
	m.previous[node.Name] = node

	if hadOld {
		return m.handler.NodeUpdate(node.Node, old.Node)
	}
	return m.handler.NodeAdd(node.Node)
}

var _ reconciler.Operations[*node.TableNode] = &proxyOps{}
