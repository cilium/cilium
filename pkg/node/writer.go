// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// Writer provides source-aware write access to the node table.
type Writer struct {
	log        *slog.Logger
	db         *statedb.DB
	nodes      statedb.RWTable[*Node]
	candidates statedb.RWTable[*nodeCandidate]

	isStaticLocalRouterIP  func(string) bool
	prefixClusterMutatorFn PrefixClusterMutatorFn

	requiredReconcilers []NodeReconciler
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
	candidates, err := newNodeCandidateTable(db)
	if err != nil {
		panic(err)
	}
	return newWriter(log, db, nodes, candidates)
}

// WriteTxn atomically updates node candidates and the selected node table.
// The transaction must be committed or aborted. Commit reconciles the
// conflict-free node table for the affected conflict components.
type WriteTxn struct {
	statedb.WriteTxn
	w      *Writer
	closed bool

	changes map[nodeCandidateKey]nodeCandidateChange
}

// WriteTxn opens a transaction for updating node candidates.
func (w *Writer) WriteTxn() *WriteTxn {
	return &WriteTxn{
		WriteTxn: w.db.WriteTxn(w.candidates, w.nodes),
		w:        w,
		changes:  map[nodeCandidateKey]nodeCandidateChange{},
	}
}

// Abort discards candidate and selected-node changes.
func (txn *WriteTxn) Abort() {
	if txn.closed {
		return
	}
	txn.closed = true
	txn.WriteTxn.Abort()
}

// Commit derives the selected node table and atomically commits both tables.
func (txn *WriteTxn) Commit() statedb.ReadTxn {
	if txn.closed {
		return nil
	}
	txn.w.reconcileChanges(txn)
	txn.closed = true
	return txn.WriteTxn.Commit()
}

// Table returns read-only access to the node table.
func (w *Writer) Table() statedb.Table[*Node] { return w.nodes }

// SetPrefixClusterMutatorFn installs the cluster-address qualification hook.
// This hook must be set during Hive invoke time.
func (w *Writer) SetPrefixClusterMutatorFn(mutator PrefixClusterMutatorFn) {
	w.prefixClusterMutatorFn = mutator
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
func (w *Writer) RegisterInitializer(txn *WriteTxn, name string) func(*WriteTxn) {
	w.checkTxn(txn)
	complete := w.nodes.RegisterInitializer(txn, name)
	return func(txn *WriteTxn) {
		w.checkTxn(txn)
		complete(txn)
	}
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

// Upsert takes ownership of n and stores it as a candidate. The caller must not
// modify n after calling Upsert. The conflict-free node table is reconciled
// when txn is committed.
func (w *Writer) Upsert(txn *WriteTxn, n *nodeTypes.Node) {
	w.checkTxn(txn)
	candidate := &nodeCandidate{node: &Node{
		Node:             *n,
		addressClusterID: deriveAddressClusterID(w.prefixClusterMutatorFn, n),
	}}
	if old, _, found := w.candidates.Get(
		txn,
		nodeCandidateByID(candidate.key().String()),
	); found && old.node.Local != nil {
		w.log.Warn("Ignoring remote update to local node",
			logfields.Node, n.Fullname(),
			logfields.Source, n.Source,
		)
		return
	}
	w.upsertCandidate(txn, candidate)
}

// Delete removes a remote node candidate from the given source. The selected
// node table is reconciled when txn is committed.
func (w *Writer) Delete(txn *WriteTxn, src source.Source, identity nodeTypes.Identity) {
	w.checkTxn(txn)
	key := nodeCandidateKey{identity, src}
	candidate, _, found := w.candidates.Get(txn, nodeCandidateByID(key.String()))
	if found && candidate.node.Local == nil {
		w.deleteCandidate(txn, candidate)
		return
	}

	if active, _, found := w.nodes.Get(txn, NodeByName(identity.String())); found {
		w.log.Warn("Ignoring node deletion from source that does not own node",
			logfields.Node, identity.Name,
			logfields.Source, src,
			logfields.NodeOwner, active.Source,
		)
	}
}

func (w *Writer) checkTxn(txn *WriteTxn) {
	if txn.w != w {
		panic("node: write transaction belongs to another Writer")
	}
	if txn.closed {
		panic("node: write transaction is closed")
	}
}

func (w *Writer) upsertCandidate(txn *WriteTxn, candidate *nodeCandidate) {
	w.prepareCandidate(candidate)
	key := candidate.key()
	old, _, found := w.candidates.Get(txn, nodeCandidateByID(key.String()))
	if found && sameCandidate(old, candidate) {
		return
	}
	if _, _, err := w.candidates.Insert(txn, candidate); err != nil {
		w.log.Error("Failed to write node candidate",
			logfields.Error, err,
			logfields.Node, candidate.node.Fullname(),
			logfields.Source, candidate.node.Source,
		)
		return
	}
	w.recordCandidateChange(txn, key, old, candidate)
}

func (w *Writer) prepareCandidate(candidate *nodeCandidate) {
	for address := range candidate.node.addressClusters(w.isStaticLocalRouterIP) {
		candidate.conflictAddresses = append(candidate.conflictAddresses, address)
	}
	slices.SortFunc(candidate.conflictAddresses, func(a, b cmtypes.AddrCluster) int {
		return a.Compare(b)
	})
	candidate.conflictAddresses = slices.Compact(candidate.conflictAddresses)
}

func sameCandidate(a, b *nodeCandidate) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.node.DeepEqual(b.node) &&
		a.node.addressClusterID == b.node.addressClusterID
}

func (w *Writer) recordCandidateChange(
	txn *WriteTxn,
	key nodeCandidateKey,
	old, new *nodeCandidate,
) {
	change, found := txn.changes[key]
	if !found {
		change.old = old
	}
	change.new = new
	if sameCandidate(change.old, change.new) {
		delete(txn.changes, key)
	} else {
		txn.changes[key] = change
	}
}

func (w *Writer) upsertLocal(txn *WriteTxn, old, candidate *Node) {
	w.checkTxn(txn)
	if old != nil && (nodeCandidateKey{old.Node.Identity(), old.Source}) !=
		(nodeCandidateKey{candidate.Node.Identity(), candidate.Source}) {
		if previous, _, found := w.candidates.Get(
			txn,
			nodeCandidateByID((nodeCandidateKey{old.Node.Identity(), old.Source}).String()),
		); found {
			w.deleteCandidate(txn, previous)
		}
	}
	candidate.addressClusterID = deriveAddressClusterID(w.prefixClusterMutatorFn, &candidate.Node)
	w.upsertCandidate(txn, &nodeCandidate{node: candidate})
}

func (w *Writer) deleteCandidate(txn *WriteTxn, candidate *nodeCandidate) {
	if _, _, err := w.candidates.Delete(txn, candidate); err != nil {
		w.log.Error("Failed to delete node candidate",
			logfields.Error, err,
			logfields.Node, candidate.node.Fullname(),
			logfields.Source, candidate.node.Source,
		)
		return
	}
	w.recordCandidateChange(txn, candidate.key(), candidate, nil)
}

// affectedCandidates returns the current candidates in every conflict
// component touched by txn, together with the node names whose selected rows
// may need updating. Candidates are connected when they have the same node
// name or share a conflict address.
//
// Both the old and new versions of each change seed the traversal. Using the
// old version is important for deletes and address changes: although it is no
// longer indexed, its name and addresses lead us to all pieces of the former
// conflict component.
func (w *Writer) affectedCandidates(txn *WriteTxn) ([]*nodeCandidate, set.Set[string]) {
	var (
		worklist         []*nodeCandidate
		candidateKeys    set.Set[nodeCandidateKey]
		affectedNames    set.Set[string]
		visitedNames     set.Set[string]
		visitedAddresses set.Set[cmtypes.AddrCluster]
	)

	addCandidate := func(candidate *nodeCandidate) {
		key := candidate.key()
		if candidateKeys.Has(key) {
			return
		}
		candidateKeys.Insert(key)
		worklist = append(worklist, candidate)
		affectedNames.Insert(candidate.node.Fullname())
	}
	visitConflicts := func(candidate *nodeCandidate) {
		name := candidate.node.Fullname()
		affectedNames.Insert(name)
		if !visitedNames.Has(name) {
			visitedNames.Insert(name)
			for other := range w.candidates.List(txn, nodeCandidateByName(name)) {
				addCandidate(other)
			}
		}
		for _, address := range candidate.conflictAddresses {
			if visitedAddresses.Has(address) {
				continue
			}
			visitedAddresses.Insert(address)
			for other := range w.candidates.List(txn, nodeCandidateByAddress(address)) {
				addCandidate(other)
			}
		}
	}

	for _, change := range txn.changes {
		if change.old != nil {
			visitConflicts(change.old)
		}
		if change.new != nil {
			visitConflicts(change.new)
		}
	}
	// worklist is both the result and the traversal queue. Visiting a candidate
	// can append previously unseen neighbors, so use an index loop whose bound
	// grows with the slice. A range loop would only visit the elements present
	// when the loop started.
	for i := 0; i < len(worklist); i++ {
		visitConflicts(worklist[i])
	}
	slices.SortFunc(worklist, compareCandidatePrecedence)
	return worklist, affectedNames
}

func (w *Writer) selectCandidates(
	txn *WriteTxn,
	candidates []*nodeCandidate,
) map[string]*nodeCandidate {
	selected := make(map[string]*nodeCandidate, len(candidates))
	addressOwners := map[cmtypes.AddrCluster]*nodeCandidate{}
	for _, candidate := range candidates {
		name := candidate.node.Fullname()
		if owner := selected[name]; owner != nil {
			if _, updated := txn.changes[candidate.key()]; updated {
				w.log.Warn("Ignoring lower priority node update",
					logfields.Node, name,
					logfields.Source, candidate.node.Source,
					logfields.NodeOwner, owner.node.Source,
				)
			}
			continue
		}

		conflict := false
		for _, address := range candidate.conflictAddresses {
			if owner := addressOwners[address]; owner != nil {
				conflict = true
				if _, updated := txn.changes[candidate.key()]; updated {
					w.log.Warn("Node address conflicts with another node",
						logfields.IPAddr, address,
						logfields.Node, name,
						logfields.Source, candidate.node.Source,
						logfields.ConflictingResource, owner.node.Fullname(),
						logfields.NodeOwner, owner.node.Source,
					)
				}
			}
		}
		if conflict {
			continue
		}

		selected[name] = candidate
		for _, address := range candidate.conflictAddresses {
			addressOwners[address] = candidate
		}
	}
	return selected
}

func sameDesiredNode(active *Node, candidate *nodeCandidate) bool {
	return active.DeepEqual(candidate.node) &&
		active.addressClusterID == candidate.node.addressClusterID
}

func (w *Writer) reconcileChanges(txn *WriteTxn) {
	if len(txn.changes) == 0 {
		return
	}
	candidates, affectedNames := w.affectedCandidates(txn)
	selected := w.selectCandidates(txn, candidates)
	existing := make(map[string]*Node, affectedNames.Len())

	for name := range affectedNames.Members() {
		active, _, found := w.nodes.Get(txn, NodeByName(name))
		if !found {
			continue
		}
		existing[name] = active
		candidate := selected[name]
		if candidate != nil && sameDesiredNode(active, candidate) {
			continue
		}
		if _, _, err := w.nodes.Delete(txn, active); err != nil {
			w.log.Error("Failed to delete node from table",
				logfields.Error, err,
				logfields.Node, active.Fullname(),
				logfields.Source, active.Source,
			)
			continue
		}
	}

	reconcilers := reconcilerNames(w.getRequiredReconcilers(txn))
	for name, candidate := range selected {
		if old := existing[name]; old != nil && sameDesiredNode(old, candidate) {
			continue
		}
		obj := candidate.node.DeepCopy()
		if old := existing[name]; old != nil {
			obj.Statuses = old.Statuses.Pending(reconcilers...)
		} else {
			obj.Statuses = reconciler.NewStatusSet().Pending(reconcilers...)
		}
		if _, _, err := w.nodes.Insert(txn, obj); err != nil {
			w.log.Error("Failed to write node to table",
				logfields.Error, err,
				logfields.Node, obj.Fullname(),
				logfields.Source, obj.Source,
			)
			continue
		}
	}
}

type writerParams struct {
	cell.In

	Log          *slog.Logger
	DB           *statedb.DB
	Nodes        statedb.RWTable[*Node]
	Candidates   statedb.RWTable[*nodeCandidate]
	DaemonConfig *option.DaemonConfig `optional:"true"`
}

func provideWriter(p writerParams) *Writer {
	w := newWriter(p.Log, p.DB, p.Nodes, p.Candidates)
	if p.DaemonConfig != nil {
		w.isStaticLocalRouterIP = p.DaemonConfig.IsLocalRouterIP
	}
	return w
}

func newWriter(
	log *slog.Logger,
	db *statedb.DB,
	nodes statedb.RWTable[*Node],
	candidates statedb.RWTable[*nodeCandidate],
) *Writer {
	return &Writer{
		log:        log,
		db:         db,
		nodes:      nodes,
		candidates: candidates,
	}
}

type nodeCandidateChange struct {
	old *nodeCandidate
	new *nodeCandidate
}

type nodeCandidateKey struct {
	identity nodeTypes.Identity
	source   source.Source
}

type nodeCandidate struct {
	node *Node

	// conflictAddresses are the normalized addresses used for conflict
	// detection and by the candidate address index.
	conflictAddresses []cmtypes.AddrCluster
}

func (candidate nodeCandidate) key() nodeCandidateKey {
	return nodeCandidateKey{candidate.node.Node.Identity(), candidate.node.Source}
}

func (candidate *nodeCandidate) TableHeader() []string {
	return []string{"Name", "Source"}
}

func (candidate *nodeCandidate) TableRow() []string {
	return []string{candidate.node.Fullname(), string(candidate.node.Source)}
}

const nodeCandidateTableName = "node-candidates"

var (
	// The primary index uniquely identifies a producer's candidate.
	nodeCandidateIDIndex = statedb.Index[*nodeCandidate, string]{
		Name: "id",
		FromObject: func(candidate *nodeCandidate) index.KeySet {
			return index.NewKeySet(index.String(candidate.key().String()))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
	nodeCandidateNameIndex = statedb.Index[*nodeCandidate, string]{
		Name: "name",
		FromObject: func(candidate *nodeCandidate) index.KeySet {
			return index.NewKeySet(index.String(candidate.node.Fullname()))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}
	nodeCandidateAddressIndex = statedb.Index[*nodeCandidate, cmtypes.AddrCluster]{
		Name: "address",
		FromObject: func(candidate *nodeCandidate) index.KeySet {
			keys := make([]index.Key, 0, len(candidate.conflictAddresses))
			for _, address := range candidate.conflictAddresses {
				keys = append(keys, nodeAddressKey(address))
			}
			return index.NewKeySet(keys...)
		},
		FromKey:    nodeAddressKey,
		FromString: nodeAddressKeyString,
		Unique:     false,
	}
	nodeCandidateByID      = nodeCandidateIDIndex.Query
	nodeCandidateByName    = nodeCandidateNameIndex.Query
	nodeCandidateByAddress = nodeCandidateAddressIndex.Query
)

func (key nodeCandidateKey) String() string {
	return string(key.source) + "\x00" + key.identity.Cluster + "\x00" + key.identity.Name
}

func compareCandidatePrecedence(a, b *nodeCandidate) int {
	return cmp.Or(
		a.node.Source.ComparePriority(b.node.Source),
		cmp.Compare(a.node.Cluster, b.node.Cluster),
		cmp.Compare(a.node.Name, b.node.Name),
		// ComparePriority treats unknown sources equally. Use the source name
		// as the final tie-breaker to produce a total, deterministic order.
		cmp.Compare(a.node.Source, b.node.Source),
	)
}

func newNodeCandidateTable(db *statedb.DB) (statedb.RWTable[*nodeCandidate], error) {
	return statedb.NewTable(
		db,
		nodeCandidateTableName,
		nodeCandidateIDIndex,
		nodeCandidateNameIndex,
		nodeCandidateAddressIndex,
	)
}
