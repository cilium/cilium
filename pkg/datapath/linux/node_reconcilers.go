package linux

import (
	"context"
	"log/slog"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

var NodeReconcilerCell = cell.Module(
	"node-reconcilers",
	"Datapath Node reconcilers",

	cell.Invoke(registerNodeReconcilers),
)

type nodeReconcilerParams struct {
	cell.In

	Log              *slog.Logger
	Table            statedb.RWTable[node.Node]
	Handler          datapath.NodeHandler
	ReconcilerParams reconciler.Params
}

func registerNodeReconcilers(p nodeReconcilerParams) error {
	proxy := reconcilerConfig("linux", &proxyOps{p.Log, p.Handler, make(map[string]node.Node)}, p.Table)
	return reconciler.Register(proxy, p.ReconcilerParams)
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
func (m *proxyOps) Prune(context.Context, statedb.ReadTxn, statedb.Iterator[node.Node]) error {
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

func reconcilerConfig(name string, ops reconciler.Operations[node.Node], tbl statedb.RWTable[node.Node]) reconciler.Config[node.Node] {
	return reconciler.Config[node.Node]{
		Table:                   tbl,
		RetryBackoffMinDuration: 100 * time.Millisecond,
		RetryBackoffMaxDuration: time.Minute,
		IncrementalRoundSize:    100,
		GetObjectStatus: func(n node.Node) reconciler.Status {
			return n.GetReconciliationStatus(name)
		},
		SetObjectStatus: func(n node.Node, s reconciler.Status) node.Node {
			return n.SetReconciliationStatus(name, s)
		},
		CloneObject:     node.Node.Clone,
		Operations:      ops,
		BatchOperations: nil,
	}
}
