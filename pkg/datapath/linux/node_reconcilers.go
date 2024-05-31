package linux

import (
	"context"
	"errors"
	"log/slog"

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
	ReconcilerParams reconciler.Params
}

func registerNodeReconcilers(p nodeReconcilerParams) error {
	mock := reconcilerConfig("mock", &mockOps{p.Log}, p.Table)
	failing := reconcilerConfig("failing", &mockFailingOps{p.Log}, p.Table)
	if err := reconciler.Register(mock, p.ReconcilerParams); err != nil {
		return err
	}
	return reconciler.Register(failing, p.ReconcilerParams)
}

type mockOps struct {
	log *slog.Logger
}

// Delete implements reconciler.Operations.
func (m *mockOps) Delete(ctx context.Context, txn statedb.ReadTxn, node node.Node) error {
	m.log.Info("Delete node", "node", node.Name())
	return nil
}

// Prune implements reconciler.Operations.
func (m *mockOps) Prune(context.Context, statedb.ReadTxn, statedb.Iterator[node.Node]) error {
	return nil
}

// Update implements reconciler.Operations.
func (m *mockOps) Update(ctx context.Context, txn statedb.ReadTxn, node node.Node) error {
	m.log.Info("Update node", "node", node.Name())
	return nil
}

var _ reconciler.Operations[node.Node] = &mockOps{}

type mockFailingOps struct {
	log *slog.Logger
}

// Delete implements reconciler.Operations.
func (m *mockFailingOps) Delete(ctx context.Context, txn statedb.ReadTxn, node node.Node) error {
	return errors.New("ohno")
}

// Prune implements reconciler.Operations.
func (m *mockFailingOps) Prune(context.Context, statedb.ReadTxn, statedb.Iterator[node.Node]) error {
	return nil
}

// Update implements reconciler.Operations.
func (m *mockFailingOps) Update(ctx context.Context, txn statedb.ReadTxn, node node.Node) error {
	return errors.New("ohno")
}

var _ reconciler.Operations[node.Node] = &mockFailingOps{}

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
