// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

// Writer provides source-aware write access to the node table.
type Writer struct {
	log   *slog.Logger
	db    *statedb.DB
	nodes statedb.RWTable[*Node]
}

// NewWriter constructs a node table writer.
func NewWriter(log *slog.Logger, db *statedb.DB, nodes statedb.RWTable[*Node]) *Writer {
	return &Writer{log: log, db: db, nodes: nodes}
}

// Table returns read-only access to the node table.
func (w *Writer) Table() statedb.Table[*Node] { return w.nodes }

// RegisterInitializer registers a producer that must finish its initial node
// listing before the table is considered initialized.
func (w *Writer) RegisterInitializer(txn statedb.WriteTxn, name string) func(statedb.WriteTxn) {
	return w.nodes.RegisterInitializer(txn, name)
}

// Refresh marks every node pending and waits for all currently known node
// reconcilers to successfully process them.
func (w *Writer) Refresh(ctx context.Context) error {
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
func (w *Writer) Upsert(txn statedb.WriteTxn, n *nodeTypes.Node) bool {
	obj := &Node{Node: *n}

	old, _, found := w.nodes.Get(txn, NodeByName(obj.Fullname()))
	if found {
		if old.Local != nil || !source.AllowOverwrite(old.Source, obj.Source) {
			return false
		}
	}

	// Resolve all address conflicts before changing the table. This keeps the
	// operation atomic when an incoming node overlaps multiple existing nodes:
	// a single stronger owner rejects the update without deleting weaker ones.
	conflicts := map[string]*Node{}
	for addr := range conflictAddresses(n) {
		for candidate := range w.nodes.List(txn, NodeByAddress(addr)) {
			if candidate.Fullname() == obj.Fullname() {
				continue
			}
			conflicts[candidate.Fullname()] = candidate
		}
	}
	for _, candidate := range conflicts {
		if candidate.Local != nil || !source.AllowOverwrite(candidate.Source, obj.Source) {
			return false
		}
	}

	changed := false
	for _, candidate := range conflicts {
		if _, _, err := w.nodes.Delete(txn, candidate); err != nil {
			w.log.Error("Failed to delete node with conflicting address",
				logfields.Error, err,
				logfields.Node, candidate.Name,
				logfields.Source, candidate.Source,
			)
			return false
		}
		changed = true
	}

	if found {
		if old.Node.DeepEqual(&obj.Node) {
			return changed
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

// conflictAddresses yields the normalized addresses whose ownership used to
// gate NodeManager datapath updates. IPv4-mapped IPv6 addresses are normalized
// to IPv4 so both representations conflict with one another.
func conflictAddresses(n *nodeTypes.Node) iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		seen := map[netip.Addr]struct{}{}
		yieldAddr := func(addr netip.Addr) bool {
			if !addr.IsValid() {
				return true
			}
			addr = addr.Unmap()
			if _, found := seen[addr]; found {
				return true
			}
			seen[addr] = struct{}{}
			return yield(addr)
		}

		for _, address := range n.IPAddresses {
			addr, ok := netip.AddrFromSlice(address.IP)
			if ok && !yieldAddr(addr) {
				return
			}
		}
		for _, addr := range []netip.Addr{
			n.IPv4HealthIP.Addr,
			n.IPv6HealthIP.Addr,
			n.IPv4IngressIP.Addr,
			n.IPv6IngressIP.Addr,
		} {
			if !yieldAddr(addr) {
				return
			}
		}
	}
}

// Delete removes a remote node if this writer's source still owns it. It
// reports whether the table changed.
func (w *Writer) Delete(txn statedb.WriteTxn, src source.Source, identity nodeTypes.Identity) bool {
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
