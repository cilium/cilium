// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

// NodeWriter provides source-aware write access to the node table.
type NodeWriter struct {
	log   *slog.Logger
	db    *statedb.DB
	nodes statedb.RWTable[*Node]
}

// NewNodeWriter constructs a node table writer.
func NewNodeWriter(log *slog.Logger, db *statedb.DB, nodes statedb.RWTable[*Node]) *NodeWriter {
	return &NodeWriter{log: log, db: db, nodes: nodes}
}

// RegisterInitializer registers a producer that must finish its initial node
// listing before the table is considered initialized.
func (w *NodeWriter) RegisterInitializer(txn statedb.WriteTxn, name string) func(statedb.WriteTxn) {
	return w.nodes.RegisterInitializer(txn, name)
}

// Refresh marks every node pending and waits for all currently known node
// reconcilers to successfully process them.
func (w *NodeWriter) Refresh(ctx context.Context) error {
	txn := w.db.WriteTxn(w.nodes)
	targets := []string{}
	for n := range w.nodes.All(txn) {
		targets = append(targets, n.Fullname())
		n = n.DeepCopy()
		n.Statuses = n.Statuses.Pending()
		if _, _, err := w.nodes.Insert(txn, n); err != nil {
			txn.Abort()
			return fmt.Errorf("marking node %s pending: %w", n.Fullname(), err)
		}
	}
	txn.Commit()

	rtxn := w.db.ReadTxn()
	for _, fullname := range targets {
		for {
			n, _, watch, found := w.nodes.GetWatch(rtxn, NodeByName(fullname))
			if !found {
				break
			}

			finished := true
			for _, status := range n.Statuses.All() {
				if status.Kind != reconciler.StatusKindDone &&
					status.Kind != reconciler.StatusKindError {
					finished = false
					break
				}
			}
			if finished {
				break
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-watch:
				rtxn = w.db.ReadTxn()
			}
		}
	}
	return nil
}

// Upsert takes ownership of n and inserts or updates it if its source is
// allowed to overwrite the current owner. The caller must not modify n after
// calling Upsert. It reports whether the table changed.
func (w *NodeWriter) Upsert(txn statedb.WriteTxn, n *nodeTypes.Node) bool {
	obj := &Node{Node: *n}

	old, _, found := w.nodes.Get(txn, NodeByName(obj.Fullname()))
	if found {
		if old.Local != nil || !source.AllowOverwrite(old.Source, obj.Source) {
			return false
		}
		if old.Node.DeepEqual(&obj.Node) {
			return false
		}
		obj.Statuses = old.Statuses.Pending()
	}

	if _, _, err := w.nodes.Insert(txn, obj); err != nil {
		w.log.Error("Failed to write node to table",
			logfields.Error, err,
			logfields.Node, obj.Name,
			logfields.Source, obj.Source,
		)
		return false
	}
	return true
}

// Delete removes a remote node if this writer's source still owns it. It
// reports whether the table changed.
func (w *NodeWriter) Delete(txn statedb.WriteTxn, src source.Source, identity nodeTypes.Identity) bool {
	old, _, found := w.nodes.Get(txn, NodeByName(identity.String()))
	if !found || old.Local != nil || old.Source != src {
		return false
	}
	if _, _, err := w.nodes.Delete(txn, old); err != nil {
		w.log.Error("Failed to delete node from table",
			logfields.Error, err,
			logfields.Node, identity.Name,
			logfields.Source, src,
		)
		return false
	}
	return true
}
