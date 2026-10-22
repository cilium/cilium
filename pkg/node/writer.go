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

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// Writer provides source-aware write access to the node table.
type Writer struct {
	log     *slog.Logger
	db      *statedb.DB
	nodes   statedb.RWTable[*Node]
	metrics *nodeMetrics

	isStaticLocalRouterIP  func(netip.Addr) bool
	prefixClusterMutatorFn PrefixClusterMutatorFn

	updatePolicy UpdatePolicy

	requiredReconcilers []NodeReconciler
}

// UpdatePolicy preserves the legacy node update ordering. It retains ownership
// of conflict resolution and any state it needs.
type UpdatePolicy interface {
	// The publish result only controls remote nodes; UpsertLocal always writes
	// the local row. The mutator is the writer's prefix qualification hook.
	Upsert(node *nodeTypes.Node, mutator PrefixClusterMutatorFn) (publish bool)
	// Delete reports whether the source owns the cached node and its published
	// row may be removed, even if that row still has an older source.
	Delete(src source.Source, identity nodeTypes.Identity, mutator PrefixClusterMutatorFn) (remove bool)
}

// PrefixClusterMutatorFn derives cluster-aware addressing options from a
// serialized node.
type PrefixClusterMutatorFn = func(*nodeTypes.Node) []cmtypes.PrefixClusterOpts

// NodeReconciler identifies a reconciler operating on the node table.
type NodeReconciler string

func (r NodeReconciler) String() string { return string(r) }

const (
	// LinuxNodeReconciler realizes nodes in the Linux datapath.
	LinuxNodeReconciler NodeReconciler = "linux"
	// WireGuardNodeReconciler realizes nodes in the WireGuard datapath.
	WireGuardNodeReconciler NodeReconciler = "wireguard"
)

// NewWriter constructs a node table writer.
func NewWriter(log *slog.Logger, db *statedb.DB, nodes statedb.RWTable[*Node]) *Writer {
	return &Writer{log: log, db: db, nodes: nodes, metrics: NewNodeMetrics()}
}

type writerParams struct {
	cell.In

	Log          *slog.Logger
	DB           *statedb.DB
	Nodes        statedb.RWTable[*Node]
	Metrics      *nodeMetrics
	DaemonConfig *option.DaemonConfig `optional:"true"`
}

func provideWriter(p writerParams) *Writer {
	w := NewWriter(p.Log, p.DB, p.Nodes)
	w.metrics = p.Metrics
	if p.DaemonConfig != nil {
		w.isStaticLocalRouterIP = p.DaemonConfig.IsLocalRouterIP
	}
	return w
}

// Table returns read-only access to the node table.
func (w *Writer) Table() statedb.Table[*Node] { return w.nodes }

// SetPrefixClusterMutatorFn installs the cluster-address qualification hook.
// This hook must be set during Hive invoke time.
func (w *Writer) SetPrefixClusterMutatorFn(mutator PrefixClusterMutatorFn) {
	w.prefixClusterMutatorFn = mutator
}

func (w *Writer) SetUpdatePolicy(p UpdatePolicy) {
	w.updatePolicy = p
}

func deriveAddressClusterID(mutator PrefixClusterMutatorFn, n *nodeTypes.Node) uint32 {
	if mutator == nil {
		return 0
	}
	// The mutator only enriches PrefixCluster metadata. The prefix itself is
	// irrelevant when extracting the derived cluster ID.
	return cmtypes.PrefixClusterFrom(netip.Prefix{}, mutator(n)...).ClusterID()
}

// RegisterInitializer registers a producer that must finish its initial node
// listing before the table is considered initialized.
func (w *Writer) RegisterInitializer(txn statedb.WriteTxn, name string) func(statedb.WriteTxn) {
	return w.nodes.RegisterInitializer(txn, name)
}

// RegisterReconciler adds the named reconciler to the list of required
// reconcilers and marks existing nodes pending for it. This list is passed to
// [reconciler.StatusSet.Pending] when nodes are created or updated.
// Panics if the reconciler has already been registered.
func (w *Writer) RegisterReconciler(name NodeReconciler) {
	txn := w.db.WriteTxn(w.nodes)
	defer txn.Abort()

	nameString := name.String()
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
		updated.Statuses = updated.Statuses.Set(nameString, reconciler.StatusPending())
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
func (w *Writer) UnregisterReconciler(name NodeReconciler) {
	txn := w.db.WriteTxn(w.nodes)
	defer txn.Abort()

	nameString := name.String()
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
		updated.Statuses = updated.Statuses.Delete(nameString)
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
func (w *Writer) getRequiredReconcilers(_ statedb.WriteTxn) []NodeReconciler {
	if w == nil {
		return nil
	}
	return slices.Clone(w.requiredReconcilers)
}

func reconcilerNames(reconcilers []NodeReconciler) []string {
	names := make([]string, len(reconcilers))
	for i, reconciler := range reconcilers {
		names[i] = reconciler.String()
	}
	return names
}

// WaitUntilReconciled waits until all nodes present in txn have been
// reconciled. When requireDone is false, both done and error statuses are
// considered finished. When it is true, every status must be done.
func (w *Writer) WaitUntilReconciled(
	ctx context.Context,
	txn statedb.ReadTxn,
	requireDone bool,
) error {
	return w.waitUntilReconciled(ctx, txn, requireDone, nil)
}

func (w *Writer) waitUntilReconciled(
	ctx context.Context,
	txn statedb.ReadTxn,
	requireDone bool,
	reconcilers []NodeReconciler,
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
				if reconcilers == nil {
					for _, status := range node.Statuses.All() {
						if status.Kind != reconciler.StatusKindDone &&
							(requireDone || status.Kind != reconciler.StatusKindError) {
							finished = false
							break
						}
					}
				} else {
					for _, name := range reconcilers {
						status := node.Statuses.Get(name.String())
						if status.Kind != reconciler.StatusKindDone &&
							(requireDone || status.Kind != reconciler.StatusKindError) {
							finished = false
							break
						}
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

// Refresh marks the selected reconcilers pending for every node and waits for
// them to attempt processing the nodes (status is either Done or Error). If no
// reconcilers are specified, all registered reconcilers are refreshed. The
// error is [ctx.Err()] if context is cancelled.
func (w *Writer) Refresh(ctx context.Context, reconcilers ...NodeReconciler) error {
	txn := w.db.WriteTxn(w.nodes)
	registered := w.getRequiredReconcilers(txn)
	if len(reconcilers) == 0 {
		reconcilers = registered
	} else {
		for _, name := range reconcilers {
			if _, found := slices.BinarySearch(registered, name); !found {
				txn.Abort()
				return fmt.Errorf("node reconciler %q is not registered", name)
			}
		}
	}
	if len(reconcilers) == 0 {
		txn.Abort()
		return nil
	}
	for n := range w.nodes.All(txn) {
		updated := *n
		for _, name := range reconcilers {
			updated.Statuses = updated.Statuses.Set(name.String(), reconciler.StatusPending())
		}
		if _, _, err := w.nodes.Insert(txn, &updated); err != nil {
			txn.Abort()
			return fmt.Errorf("marking node %s pending: %w", updated.Fullname(), err)
		}
	}
	rtxn := txn.Commit()

	// Wait until refresh of all nodes has been attempted.
	return w.waitUntilReconciled(ctx, rtxn, false, reconcilers)
}

// UpsertLocal writes the local node, including its local-only information, and
// runs the update policy for its side effects once the local node is initialized.
// The local node is always written independently of whether the policy would
// publish a remote node.
func (w *Writer) UpsertLocal(txn statedb.WriteTxn, n *LocalNode) error {
	if n.Local == nil {
		panic("UpsertLocal: local node information is missing")
	}

	old, _, _ := w.nodes.Get(txn, LocalNodeQuery)
	event := "add"
	if old != nil {
		event = "update"
	}
	w.metrics.EventsReceived.WithLabelValues(event, string(n.Source)).Inc()
	if err := w.writeNode(txn, n, old); err != nil {
		return fmt.Errorf("write local node: %w", err)
	}
	w.metrics.NumNodes.Set(float64(w.nodes.NumObjects(txn)))
	if w.updatePolicy != nil &&
		!slices.Contains(w.nodes.PendingInitializers(txn), LocalNodeTableInitializerName) {
		w.updatePolicy.Upsert(&n.Node, w.prefixClusterMutatorFn)
	}
	return nil
}

// Upsert a remote node into the node table.
func (w *Writer) Upsert(txn statedb.WriteTxn, n *nodeTypes.Node) bool {
	old, _, found := w.nodes.Get(txn, NodeByName(n.Fullname()))
	if n.IsLocal() || (found && old.Local != nil) {
		w.log.Warn("Rejecting update to local node",
			logfields.Node, n.Fullname(),
			logfields.Source, n.Source,
		)
		return false
	}
	event := "add"
	if found {
		event = "update"
	}
	w.metrics.EventsReceived.WithLabelValues(event, string(n.Source)).Inc()
	if w.updatePolicy != nil && !w.updatePolicy.Upsert(n, w.prefixClusterMutatorFn) {
		// Policy rejected the update due to conflict.
		return false
	}

	obj := &Node{
		Node:             *n,
		addressClusterID: deriveAddressClusterID(w.prefixClusterMutatorFn, n),
	}

	if found {
		if old.Node.DeepEqual(&obj.Node) &&
			old.addressClusterID == obj.addressClusterID {
			return false
		}
	}

	if err := w.writeNode(txn, obj, old); err != nil {
		w.log.Error("Failed to write node to table",
			logfields.Error, err,
			logfields.Node, obj.Name,
			logfields.Source, obj.Source,
		)
		return false
	}
	w.metrics.NumNodes.Set(float64(w.nodes.NumObjects(txn)))
	return true
}

func (w *Writer) writeNode(txn statedb.WriteTxn, n, old *Node) error {
	if old != nil {
		n.Statuses = old.Statuses
		if old.Fullname() != n.Fullname() {
			if _, _, err := w.nodes.Delete(txn, old); err != nil {
				return fmt.Errorf("delete previous node: %w", err)
			}
		}
	}
	n.Statuses = n.Statuses.Pending(reconcilerNames(w.getRequiredReconcilers(txn))...)
	_, _, err := w.nodes.Insert(txn, n)
	return err
}

// Delete removes a remote node if the policy accepts the deletion, or, without
// a policy, if src still owns the table row. It reports whether the table changed.
func (w *Writer) Delete(txn statedb.WriteTxn, src source.Source, identity nodeTypes.Identity) bool {
	w.metrics.EventsReceived.WithLabelValues("delete", string(src)).Inc()
	if w.updatePolicy != nil {
		if !w.updatePolicy.Delete(src, identity, w.prefixClusterMutatorFn) {
			return false
		}
	}
	n := &nodeTypes.Node{Name: identity.Name, Cluster: identity.Cluster}
	old, _, found := w.nodes.Get(txn, NodeByName(n.Fullname()))
	if !found {
		return false
	}
	if old.Local != nil || (w.updatePolicy == nil && old.Source != src) {
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
	w.metrics.NumNodes.Set(float64(w.nodes.NumObjects(txn)))
	return true
}
