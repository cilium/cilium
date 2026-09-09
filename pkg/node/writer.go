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
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// Writer provides source-aware write access to the node table.
type Writer struct {
	log   *slog.Logger
	db    *statedb.DB
	nodes statedb.RWTable[*Node]

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
	return &Writer{log: log, db: db, nodes: nodes}
}

type writerParams struct {
	cell.In

	Log   *slog.Logger
	DB    *statedb.DB
	Nodes statedb.RWTable[*Node]
}

func provideWriter(p writerParams) *Writer {
	return NewWriter(p.Log, p.DB, p.Nodes)
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

// Upsert takes ownership of n and inserts or updates it if its source is
// allowed to overwrite the current owner. The caller must not modify n after
// calling Upsert. It reports whether the table changed. Updates whose internal
// or external node IP conflicts with the local node are rejected, as are
// updates whose allocation CIDRs overlap the local node's allocation CIDRs or
// contain one of those protected local addresses.
func (w *Writer) Upsert(txn statedb.WriteTxn, n *nodeTypes.Node) bool {
	reconcilers := reconcilerNames(w.getRequiredReconcilers(txn))
	obj := &Node{
		Node:             *n,
		addressClusterID: deriveAddressClusterID(w.prefixClusterMutatorFn, n),
		Statuses:         reconciler.NewStatusSet().Pending(reconcilers...),
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
		if old.Node.DeepEqual(&obj.Node) &&
			old.addressClusterID == obj.addressClusterID {
			return false
		}
	}

	if local, _, localFound := w.nodes.Get(txn, LocalNodeQuery); localFound {
		if addr, conflict := conflictingLocalNodeAddress(local, obj); conflict {
			w.log.Warn("Ignoring node update that conflicts with local node address",
				logfields.IPAddr, addr,
				logfields.Node, obj.Fullname(),
				logfields.Source, obj.Source,
				logfields.ConflictingResource, local.Fullname(),
				logfields.NodeOwner, local.Source,
			)
			return false
		}
		if cidr, conflict := conflictingLocalNodeCIDR(local, obj); conflict {
			w.log.Warn("Ignoring node update whose allocation CIDR conflicts with local node",
				logfields.CIDR, cidr,
				logfields.Node, obj.Fullname(),
				logfields.Source, obj.Source,
				logfields.ConflictingResource, local.Fullname(),
				logfields.NodeOwner, local.Source,
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

func conflictingLocalNodeAddress(local, remote *Node) (netip.Addr, bool) {
	for _, remoteAddress := range remote.IPAddresses {
		if !protectedNodeAddressType(remoteAddress.Type) {
			continue
		}
		remoteIP, ok := netip.AddrFromSlice(remoteAddress.IP)
		if !ok {
			continue
		}
		remoteIP = remoteIP.Unmap()

		for _, localAddress := range local.IPAddresses {
			if !protectedNodeAddressType(localAddress.Type) {
				continue
			}
			localIP, ok := netip.AddrFromSlice(localAddress.IP)
			if ok && remoteIP == localIP.Unmap() {
				return remoteIP, true
			}
		}
	}
	return netip.Addr{}, false
}

func protectedNodeAddressType(addressType addressing.AddressType) bool {
	return addressType == addressing.NodeInternalIP ||
		addressType == addressing.NodeExternalIP
}

func conflictingLocalNodeCIDR(local, remote *Node) (netip.Prefix, bool) {
	localCIDRs := slices.Concat(local.GetIPv4AllocCIDRs(), local.GetIPv6AllocCIDRs())
	remoteCIDRs := slices.Concat(remote.GetIPv4AllocCIDRs(), remote.GetIPv6AllocCIDRs())

	for _, remoteCIDR := range remoteCIDRs {
		for _, localCIDR := range localCIDRs {
			if remoteCIDR.Overlaps(localCIDR) {
				return remoteCIDR, true
			}
		}

		for _, localAddress := range local.IPAddresses {
			if !protectedNodeAddressType(localAddress.Type) {
				continue
			}
			localIP, ok := netip.AddrFromSlice(localAddress.IP)
			if ok && remoteCIDR.Contains(localIP.Unmap()) {
				return remoteCIDR, true
			}
		}
	}
	return netip.Prefix{}, false
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
