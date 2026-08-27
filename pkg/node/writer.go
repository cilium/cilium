// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// Writer provides source-aware write access to the node table.
type Writer struct {
	log   *slog.Logger
	db    *statedb.DB
	nodes statedb.RWTable[*Node]

	isStaticLocalRouterIP func(string) bool

	requiredReconcilers []string
}

// NewWriter constructs a node table writer.
func NewWriter(log *slog.Logger, db *statedb.DB, nodes statedb.RWTable[*Node]) *Writer {
	return &Writer{log: log, db: db, nodes: nodes}
}

type writerParams struct {
	cell.In

	Log          *slog.Logger
	DB           *statedb.DB
	Nodes        statedb.RWTable[*Node]
	DaemonConfig *option.DaemonConfig `optional:"true"`
}

func provideWriter(p writerParams) *Writer {
	w := NewWriter(p.Log, p.DB, p.Nodes)
	if p.DaemonConfig != nil {
		w.isStaticLocalRouterIP = p.DaemonConfig.IsLocalRouterIP
	}
	return w
}

// Table returns read-only access to the node table.
func (w *Writer) Table() statedb.Table[*Node] { return w.nodes }

// RegisterInitializer registers a producer that must finish its initial node
// listing before the table is considered initialized.
func (w *Writer) RegisterInitializer(txn statedb.WriteTxn, name string) func(statedb.WriteTxn) {
	return w.nodes.RegisterInitializer(txn, name)
}

// RegisterReconciler adds the named reconciler to the list of required
// reconcilers and marks existing nodes pending for it. This list is passed to
// [reconciler.StatusSet.Pending] when nodes are created or updated.
// Panics if the reconciler has already been registered.
func (w *Writer) RegisterReconciler(name string) {
	txn := w.db.WriteTxn(w.nodes)
	defer txn.Abort()

	i, found := slices.BinarySearch(w.requiredReconcilers, name)
	if found {
		panic(fmt.Sprintf("Reconciler %q already registered", name))
	}
	requiredReconcilers := slices.Insert(
		slices.Clone(w.requiredReconcilers),
		i,
		name,
	)

	// RegisterReconciler may be called from a start hook after node producers
	// have populated the table. Materialize the new pending status so observers
	// cannot mistake another reconciler completing for full reconciliation.
	for n := range w.nodes.All(txn) {
		updated := *n
		updated.Statuses = updated.Statuses.Set(name, reconciler.StatusPending())
		if _, _, err := w.nodes.Insert(txn, &updated); err != nil {
			w.log.Error("Failed to register node reconciler status",
				logfields.Error, err,
				logfields.Name, name,
			)
			return
		}
	}
	w.requiredReconcilers = requiredReconcilers
	txn.Commit()
}

// UnregisterReconciler removes the reconciler from the list of required
// reconcilers and removes its status from every node. The reconciler must be
// stopped before it is unregistered so it cannot write its status back.
func (w *Writer) UnregisterReconciler(name string) {
	txn := w.db.WriteTxn(w.nodes)
	defer txn.Abort()

	i, found := slices.BinarySearch(w.requiredReconcilers, name)
	if !found {
		return
	}
	requiredReconcilers := slices.Delete(
		slices.Clone(w.requiredReconcilers),
		i,
		i+1,
	)

	// Remove the reconciler from the nodes so it will no longer be waited for.
	for n := range w.nodes.All(txn) {
		updated := *n
		updated.Statuses = updated.Statuses.Delete(name)
		if _, _, err := w.nodes.Insert(txn, &updated); err != nil {
			w.log.Error("Failed to unregister node reconciler",
				logfields.Error, err,
				logfields.Name, name,
			)
			return
		}
	}

	w.requiredReconcilers = requiredReconcilers
	txn.Commit()
}

// getRequiredReconcilers must only be called while holding a write transaction
// for the node table. The transaction serializes access to the registry.
func (w *Writer) getRequiredReconcilers(_ statedb.WriteTxn) []string {
	if w == nil {
		return nil
	}
	return slices.Clone(w.requiredReconcilers)
}

// WaitUntilReconciled waits until all nodes present in txn have been
// reconciled. When requireDone is false, both done and error statuses are
// considered finished. When it is true, every status must be done.
func (w *Writer) WaitUntilReconciled(
	ctx context.Context,
	txn statedb.ReadTxn,
	requireDone bool,
) error {
	const settleTime = 10 * time.Millisecond

	targets := map[string]statedb.Revision{}
	for n := range w.nodes.All(txn) {
		targets[n.Fullname()] = 0
	}

	ws := statedb.NewWatchSet()
	for {
		// Iteration is faster than individual lookups and we assume that the set
		// of nodes in [targets] is mostly the same as what we see in later
		// transactions.
		allNodes, watch := w.nodes.AllWatch(txn)
		rev := w.nodes.Revision(txn)

		for node := range allNodes {
			if _, found := targets[node.Fullname()]; found {
				finished := true
				for _, status := range node.Statuses.All() {
					if status.Kind != reconciler.StatusKindDone &&
						(requireDone || status.Kind != reconciler.StatusKindError) {
						finished = false
						break
					}
				}
				if finished {
					delete(targets, node.Fullname())
				} else {
					targets[node.Fullname()] = rev
				}
			}
		}

		// Remove targets that have disappeared
		maps.DeleteFunc(targets, func(_ string, targetRev statedb.Revision) bool {
			return targetRev != rev
		})

		if len(targets) == 0 {
			break
		}

		ws.Add(watch)
		if _, err := ws.Wait(ctx, settleTime); err != nil {
			return err
		}
		txn = w.db.ReadTxn()
	}
	return nil
}

// Refresh marks every node pending and waits for all currently known node
// reconcilers have attempted to process them (status is either Done or Error).
// The error is [ctx.Err()] if context is cancelled.
func (w *Writer) Refresh(ctx context.Context) error {
	txn := w.db.WriteTxn(w.nodes)
	reconcilers := w.getRequiredReconcilers(txn)
	for n := range w.nodes.All(txn) {
		updated := *n
		updated.Statuses = updated.Statuses.Pending(reconcilers...)
		if _, _, err := w.nodes.Insert(txn, &updated); err != nil {
			txn.Abort()
			return fmt.Errorf("marking node %s pending: %w", updated.Fullname(), err)
		}
	}
	rtxn := txn.Commit()

	// Wait until refresh of all nodes has been attempted.
	return w.WaitUntilReconciled(ctx, rtxn, false)
}

// Upsert takes ownership of n and inserts or updates it if its source is
// allowed to overwrite the current owner. The caller must not modify n after
// calling Upsert. It reports whether the table changed. Conflicting weaker
// objects are not retained, so their producer must upsert them again if the
// winning object is later deleted.
func (w *Writer) Upsert(txn statedb.WriteTxn, n *nodeTypes.Node) bool {
	reconcilers := w.getRequiredReconcilers(txn)
	obj := &Node{
		Node:     *n,
		Statuses: reconciler.NewStatusSet().Pending(reconcilers...),
	}

	old, _, found := w.nodes.Get(txn, NodeByName(obj.Fullname()))
	if found {
		if old.Local != nil || !source.AllowOverwrite(old.Source, obj.Source) {
			w.log.Warn("Ignoring node update from lower priority source",
				logfields.Node, obj.Fullname(),
				logfields.Source, old.Source,
				logfields.NodeOwner, obj.Source,
			)
			return false
		}
		if old.Node.DeepEqual(&obj.Node) {
			return false
		}
	}

	// Resolve all address conflicts before changing the table. This keeps the
	// operation atomic when an incoming node overlaps multiple existing nodes:
	// a single stronger owner rejects the update without deleting weaker ones.
	conflicts := map[string]*Node{}
	for _, addr := range w.conflictAddresses(n) {
		for candidate := range w.nodes.List(txn, NodeByAddress(addr)) {
			if candidate.Fullname() == obj.Fullname() {
				continue
			}
			w.log.Warn("Node address conflicts with another node",
				logfields.IPAddr, addr,
				logfields.Node, obj.Fullname(),
				logfields.Source, obj.Source,
				logfields.ConflictingResource, candidate.Fullname(),
				logfields.NodeOwner, candidate.Source,
			)
			conflicts[candidate.Fullname()] = candidate
		}
	}
	for _, candidate := range conflicts {
		if candidate.Local != nil || !source.AllowOverwrite(candidate.Source, obj.Source) {
			return false
		}
	}

	for _, candidate := range conflicts {
		if _, _, err := w.nodes.Delete(txn, candidate); err != nil {
			w.log.Error("Failed to delete node with conflicting address",
				logfields.Error, err,
				logfields.Node, candidate.Name,
				logfields.Source, candidate.Source,
			)
			return false
		}
	}

	if found {
		obj.Statuses = old.Statuses.Pending(reconcilers...)
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

// conflictAddresses returns the normalized addresses whose ownership used to
// gate NodeManager datapath updates. Configured Cilium internal router IPs are
// omitted because they may intentionally be shared by every node. IPv4-mapped
// IPv6 addresses are normalized to IPv4 so both representations conflict with
// one another.
func (w *Writer) conflictAddresses(n *nodeTypes.Node) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(n.IPAddresses)+4)
	appendAddr := func(addr netip.Addr) {
		if addr.IsValid() {
			addrs = append(addrs, addr.Unmap())
		}
	}

	for _, address := range n.IPAddresses {
		// In delegated IPAM mode the local router IP is configured statically and is the same
		// on all nodes. Exempt the conflict in those cases.
		if address.Type == addressing.NodeCiliumInternalIP &&
			w.isStaticLocalRouterIP != nil &&
			w.isStaticLocalRouterIP(address.ToString()) {
			continue
		}
		if addr, ok := netip.AddrFromSlice(address.IP); ok {
			appendAddr(addr)
		}
	}
	appendAddr(n.IPv4HealthIP.Addr)
	appendAddr(n.IPv6HealthIP.Addr)
	appendAddr(n.IPv4IngressIP.Addr)
	appendAddr(n.IPv6IngressIP.Addr)

	slices.SortFunc(addrs, netip.Addr.Compare)
	return slices.Compact(addrs)
}

// Delete removes a remote node if this writer's source still owns it. It
// reports whether the table changed.
func (w *Writer) Delete(txn statedb.WriteTxn, src source.Source, identity nodeTypes.Identity) bool {
	old, _, found := w.nodes.Get(txn, NodeByName(identity.String()))
	if !found {
		return false
	}
	if old.Local != nil || old.Source != src {
		w.log.Warn("Ignoring node deletion from source that does not own node",
			logfields.Node, identity.Name,
			logfields.Source, src,
			logfields.NodeOwner, old.Source,
		)
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
