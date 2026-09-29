// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"maps"
	"slices"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// rollbackState owns the node's live caller/response lifecycles. Methods borrow
// node or transaction context for desired resources and publication; they never
// take the cache lock or invoke user callbacks. All access requires cacheImpl.mutex.
type rollbackState struct {
	// Response outcome releases these inverses independently of caller lifetime.
	responses set.Set[*rollbackLifecycle]
	// Caller resolution is terminal; these are live inverses, not history.
	callers set.Set[*rollbackLifecycle]
}

// resourceRollbackState owns rollback bookkeeping for one resource type.
// Embedded in resourceTypeState, it shares the same cache lock. Empty state
// allocates nothing; only live removal transactions need an owners map.
type resourceRollbackState struct {
	// A response claims the unsent lifecycle before it can coalesce further.
	unsent *rollbackLifecycle
	owners map[rollbackOwnerKey]uint32
}

type rollbackTracking uint8

const (
	// noRollbackTracking is used only for caller- or response-driven reverts,
	// which must not create additional rollback ownership for the corrective update.
	noRollbackTracking                rollbackTracking = iota
	responseRollbackTracking                           // cache-owned NACK rollback only
	callerAndResponseRollbackTracking                  // cache-owned NACK and caller-owned rollback
)

// rollbackLifecycle owns one rollback opportunity, either for the caller's
// enclosing operation or for an Envoy response covering one or more cache
// transactions. These lifetimes are independent: caller resolution does not
// disable response-driven recovery.
//
// Revert restores only resources whose expected API transactions still match;
// Finalize releases lifecycle ownership without changing desired state. Caller
// resolution is terminal even if Revert fails, whereas a failed response-driven
// revert retains its recovery state. The lifecycle is resolved when resources
// is nil and inverse is empty. Mutable state and ownership bookkeeping are
// protected by cache.mutex. A NACK may rebase its inverse targets to bypass a
// rejected predecessor, without changing its expected transactions.
type rollbackLifecycle struct {
	cache   *cacheImpl
	ctx     context.Context
	nodeID  string
	typeURL typeurl.Index
	// generation is the response inverse's boundary. For a caller inverse
	// (resources == nil), it stores the original API transaction's generation;
	// only that case converts it back to a TransactionID for the revert guard.
	generation callbacks.Generation
	resources  *rollbackResources
	inverse    resources
}

type rollbackOwnerKey struct {
	name        string
	transaction callbacks.TransactionID
}

type rollbackEntry struct {
	previous resourceEntry
	// expectedTransaction identifies the API change this inverse can undo.
	expectedTransaction callbacks.TransactionID
	// Only multi-resource API transactions need extra membership information.
	// Coalescing must keep their still-live siblings together even
	// if this particular resource is updated again before it is sent.
	transactions set.Set[callbacks.TransactionID]
}

type rollbackResources typeurl.Slots[map[string]rollbackEntry]

// preparePublicationLocked coalesces rollback ownership for committed entries.
// Save recovery maps only when immediate publication can fail. The node is
// borrowed from tx; the ledger does not allocate another owner or retain a
// back-pointer to desired state. Caller must hold cacheImpl.mutex.
func (r *rollbackState) preparePublicationLocked(tx *resourceTransaction, changedTypeURLs typeurl.Set, options resourceUpdateOptions) (oldPending *pendingPublication, oldPendingValue pendingPublication, willFinalize bool) {
	state := tx.state
	dirtyTypeURLs := snapshotTypesChangedBy(changedTypeURLs)
	// Dependent resource types can need projection updates without acquiring rollback.
	watchTypeURLs := changedTypeURLs
	oldPending = state.pendingPublication
	mergedTypeURLs := dirtyTypeURLs
	var rollbacks typeurl.Map[rollbackResources]
	if oldPending != nil {
		oldPendingValue = *oldPending
		mergedTypeURLs = oldPending.changedTypeURLs.Union(dirtyTypeURLs)
		watchTypeURLs = oldPending.watchTypeURLs.Union(watchTypeURLs)
		rollbacks = oldPending.rollbacks
	}
	willFinalize = state.hasOpenWatchLocked(watchTypeURLs)
	if willFinalize && oldPending != nil {
		// Only publication can fail after resources have been committed. Keep a
		// defensive copy for that rare path without cloning unpublished rollback
		// maps on every ordinary mutation.
		oldPendingValue.rollbacks = clonePendingRollbacks(oldPending.rollbacks)
	}
	if options.tracking != noRollbackTracking {
		rollbacks = r.mergePending(state, rollbacks, changedTypeURLs, options.inverse, tx.generation.TransactionID())
	}
	// Add finalization-only entries after building rollbacks, which omits empty
	// inverses. Preserve any rollback already stored for the same type.
	for typeURL := range typeurl.Indices() {
		if !rollbacks.Has(typeURL) && (dirtyTypeURLs.Has(typeURL) || options.waits.Has(typeURL)) {
			rollbacks.Set(typeURL, rollbackResources{})
		}
	}
	pending := oldPending
	if pending == nil {
		pending = &pendingPublication{}
	}
	*pending = pendingPublication{
		generation:      tx.generation,
		changedTypeURLs: mergedTypeURLs,
		watchTypeURLs:   watchTypeURLs,
		rollbacks:       rollbacks,
	}
	state.pendingPublication = pending
	return oldPending, oldPendingValue, willFinalize
}

// restorePublicationLocked reacquires saved ownership before releasing the
// failed replacement, so shared tombstones remain continuously guarded.
func (r *rollbackState) restorePublicationLocked(state *nodeState, oldPending *pendingPublication, oldPendingValue pendingPublication) {
	if oldPending != nil {
		r.acquireSet(state, oldPendingValue.rollbacks)
	}
	r.releaseSet(state, state.pendingPublication.rollbacks)
	if oldPending == nil {
		state.pendingPublication = nil
	} else {
		*oldPending = oldPendingValue
		state.pendingPublication = oldPending
	}
}

// publishedLocked transfers pending inverses to unsent response ownership only
// after snapshot installation succeeds. Caller must hold cacheImpl.mutex.
func (r *rollbackState) publishedLocked(c *cacheImpl, state *nodeState, pending *pendingPublication, oldSnapshot, newSnapshot cache.ResourceSnapshot) {
	// Retain rollback only for resource types whose published version changed.
	// Until go-control-plane actually produces a response, repeated published
	// generations are coalesced into one rollback per type. An older mutation
	// without a WaitGroup may precede a tracked mutation in the same eventual
	// response, and a NACK must restore the state before that whole batch.
	for typeURL, rollback := range pending.rollbacks.All() {
		if rollback.empty() {
			continue
		}
		versionChanged := oldSnapshot == nil ||
			oldSnapshot.GetVersion(typeURL.URL()) != newSnapshot.GetVersion(typeURL.URL())
		if !versionChanged {
			r.release(state, rollback)
			continue
		}
		r.retainUnsentLocked(c, state, typeURL, pending.generation, rollback, newSnapshot)
	}
}

// retainUnsentLocked keeps one coalesced rollback for a resource type
// until go-control-plane produces a response carrying the current version.
// Register it before delivery so the response can acquire its inverse even
// when the caller supplied no WaitGroup. A reconnecting client's echoed version
// alone cannot prove which names it received; retain the inverse until an
// actual response establishes acceptance or rejection.
func (r *rollbackState) retainUnsentLocked(c *cacheImpl, state *nodeState, typeURL typeurl.Index, generation callbacks.Generation, rollback rollbackResources, snapshot cache.ResourceSnapshot) {
	nodeID := state.nodeID
	if existing := state.typeStates[typeURL].rollbacks.unsent; existing != nil && !existing.completedLocked() {
		if c.completionCbs.CoalesceUnsentTypeGeneration(nodeID, typeURL, existing.generation, generation, nil) {
			*existing.resources = existing.resources.mergeHistory(state, rollback)
			if existing.resources.hasTransactions() {
				c.completionCbs.SetGenerationTransactions(nodeID, typeURL, generation, existing.resources.transactionIDs(state, snapshot))
			}
			existing.resources.pruneUnobservableResources(state, snapshot)
			existing.generation = generation
			if !existing.resources.hasObservableResources(snapshot, typeURL) && c.completionCbs.DiscardUnsentTypeGeneration(nodeID, typeURL, generation) {
				// The cache lock prevents a response from claiming this unsent
				// generation between coalescing it and discarding it.
				// No observable primary changes remain. Other-type transaction
				// members and caller-owned inverses keep their own lifecycles.
				r.finalizeLocked(state, existing)
			}
			return
		}
		// A response claimed the existing generation before its callback ran.
		// Leave that lifecycle response-owned and start another unsent chain.
		state.typeStates[typeURL].rollbacks.unsent = nil
	}
	if !rollback.hasObservableResources(snapshot, typeURL) {
		r.release(state, rollback)
		return
	}

	// Response rollback must outlive the context of the mutation which created
	// it. A later NACK remains actionable after that caller has timed out.
	lifecycle := r.newResponseLocked(c, state, typeURL, generation, rollback)
	c.completionCbs.AddTypeGenerationWithRollback(generation, typeURL, nodeID, lifecycle, nil)
	state.typeStates[typeURL].rollbacks.unsent = lifecycle
	if rollback.hasTransactions() {
		c.completionCbs.SetGenerationTransactions(nodeID, typeURL, generation, rollback.transactionIDs(state, snapshot))
	}
	rollback.pruneUnobservableResources(state, snapshot)
}

// claimResponseLocked freezes only transactions represented by this
// response. Independent, unrequested resources must remain unsent/coalescible.
// Entries sharing an expected transaction belong to the same API transaction;
// keep all of them together even when only one member was delivered.
func (r *rollbackState) claimResponseLocked(c *cacheImpl, state *nodeState, typeURL typeurl.Index, response cache.Response) {
	nodeID := state.nodeID
	lifecycle := state.typeStates[typeURL].rollbacks.unsent
	if lifecycle == nil || lifecycle.resources == nil {
		return
	}
	resources := *lifecycle.resources
	// Full-state wildcard groups need no name map. Named groups (and types
	// without implicit deletion) capture their actual requirements once here.
	if callbacks.ResponseCoversType(response, lifecycle.generation) &&
		(typeURL == typeurl.Listener || typeURL == typeurl.Cluster || typeURL == typeurl.NetworkPolicy || typeURL == typeurl.NetworkPolicyHosts) {
		c.completionCbs.CoalesceUnsentTypeGeneration(nodeID, typeURL, lifecycle.generation, lifecycle.generation, &callbacks.ResourceScope{})
		state.typeStates[typeURL].rollbacks.unsent = nil
		return
	}
	var selected set.Set[callbacks.TransactionID]
	for name, entry := range resources[typeURL] {
		if callbacks.ResponseCoversResource(response, name, entry.expectedTransaction) {
			selected.Insert(entry.expectedTransaction)
			selected.Merge(entry.transactions)
		}
	}
	// Follow the history of selected transactions, retaining still-owned siblings.
	// A newer unrequested transaction carrying an older transaction tag is not a
	// member of that older transaction anymore: leave it unsent and coalescible.
	for {
		before := selected.Len()
		for _, entries := range resources {
			for _, entry := range entries {
				if selected.Has(entry.expectedTransaction) {
					selected.Merge(entry.transactions)
				}
			}
		}
		if selected.Len() == before {
			break
		}
	}
	if selected.Empty() {
		return
	}
	var sent rollbackResources
	var sentGeneration, remainingGeneration callbacks.Generation
	for index := range typeurl.Indices() {
		for name, entry := range resources[index] {
			if selected.Has(entry.expectedTransaction) {
				if sent[index] == nil {
					sent[index] = make(map[string]rollbackEntry)
				}
				sent[index][name] = entry
				delete(resources[index], name)
				if index == typeURL {
					sentGeneration = sentGeneration.MaxTransaction(entry.expectedTransaction)
				}
			} else if index == typeURL {
				remainingGeneration = remainingGeneration.MaxTransaction(entry.expectedTransaction)
			}
		}
		if len(resources[index]) == 0 {
			resources[index] = nil
		}
	}
	if resources.empty() {
		// All primary members belong to the selected transaction. Partial ACKs
		// must still leave its complete payload available for a later NACK.
		*lifecycle.resources = sent
		scope := lifecycle.resourceScope(response)
		c.completionCbs.CoalesceUnsentTypeGeneration(nodeID, typeURL, lifecycle.generation, lifecycle.generation, scope)
		state.typeStates[typeURL].rollbacks.unsent = nil
		return
	}
	oldGeneration := lifecycle.generation
	*lifecycle.resources = resources
	lifecycle.generation = remainingGeneration
	sentLifecycle := r.newResponseLocked(c, state, typeURL, sentGeneration, sent)
	sentScope := sentLifecycle.resourceScope(response)
	c.completionCbs.PartitionUnsentTypeGeneration(nodeID, typeURL, oldGeneration,
		remainingGeneration, lifecycle, nil, sentGeneration, sentLifecycle, sentScope)
	snapshot, _ := c.SnapshotCache.GetSnapshot(nodeID)
	c.completionCbs.SetGenerationTransactions(nodeID, typeURL, remainingGeneration, resources.transactionIDs(state, snapshot))
	c.completionCbs.SetGenerationTransactions(nodeID, typeURL, sentGeneration, sent.transactionIDs(state, snapshot))
}

// newResponseLocked owns one rollback view until it is either finalized or
// reverted. Duplicate resolution calls are programming errors, but are
// deliberately harmless because the lifecycle crosses several asynchronous
// ownership boundaries.
// Caller must hold c.mutex.
func (r *rollbackState) newResponseLocked(c *cacheImpl, state *nodeState, typeURL typeurl.Index, generation callbacks.Generation, resources rollbackResources) *rollbackLifecycle {
	lifecycle := &rollbackLifecycle{
		cache:      c,
		ctx:        context.Background(),
		nodeID:     state.nodeID,
		typeURL:    typeURL,
		generation: generation,
		resources:  &resources,
	}
	r.responses.Insert(lifecycle)
	return lifecycle
}

// newCallerLocked records the originating API mutation, not a later
// response boundary or corrective publication.
// Caller must hold c.mutex.
func (r *rollbackState) newCallerLocked(tx *resourceTransaction, inverse resources) *rollbackLifecycle {
	lifecycle := &rollbackLifecycle{
		cache:      tx.cache,
		ctx:        tx.ctx,
		nodeID:     tx.nodeID,
		typeURL:    typeurl.Count,
		generation: tx.generation,
		inverse:    inverse,
	}
	r.callers.Insert(lifecycle)
	return lifecycle
}

// finalizeLocked consumes the payload and releases its ownership references.
// Caller Revert is terminal even if it fails. Response Revert retains its
// payload on failure so a later NACK can retry recovery.
// Caller must hold cacheImpl.mutex.
func (r *rollbackState) finalizeLocked(state *nodeState, lifecycle *rollbackLifecycle) {
	if lifecycle.completedLocked() {
		lifecycle.warnDuplicateLocked("finalize")
		return
	}
	responseResources, inverse := lifecycle.resources, lifecycle.inverse
	lifecycle.resources = nil
	lifecycle.inverse = resources{}
	if lifecycle.typeURL < typeurl.Count && state.typeStates[lifecycle.typeURL].rollbacks.unsent == lifecycle {
		state.typeStates[lifecycle.typeURL].rollbacks.unsent = nil
	}
	r.responses.Remove(lifecycle)
	r.callers.Remove(lifecycle)
	if responseResources == nil {
		r.releaseInverse(state, inverse, lifecycle.generation.TransactionID())
	} else {
		r.release(state, *responseResources)
	}
}

// Finalize releases the caller-owned rollback state after the enclosing
// transaction succeeds.
func (lifecycle *rollbackLifecycle) Finalize() {
	c := lifecycle.cache
	c.mutex.Lock()
	state := c.getNodeState(lifecycle.nodeID)
	state.rollbacks.finalizeLocked(state, lifecycle)
	c.mutex.Unlock()
}

// Revert restores desired resources after a caller failure or an Envoy NACK.
// Each resource's transaction fences its revert. Its previous value and
// transaction are restored with a fresh revision, fencing ACK waits for restored
// state against older responses. Published snapshots remain immutable; a corrective
// snapshot uses the resulting desired state rather than reinstalling an older
// snapshot. Unrelated later mutations are left unchanged.
// A caller's Revert is terminal regardless of its returned error. Response-owned
// recovery is independent and retains its payload on validation or publication
// failure so a subsequent NACK can retry it.
func (lifecycle *rollbackLifecycle) Revert() error {
	c := lifecycle.cache
	// Compensation must remain possible after the original mutation's caller
	// has timed out. Preserve context values without inheriting cancellation.
	tx := c.beginResourceTransaction(context.WithoutCancel(lifecycle.ctx), lifecycle.nodeID)
	defer tx.complete()
	return tx.revertLocked([]Rollback{lifecycle})
}

// prepareRevertLocked composes the selected inverses without mutating desired
// resources. Rejected predecessors are rebased before the atomic correction.
// Caller must hold cacheImpl.mutex.
func (r *rollbackState) prepareRevertLocked(tx *resourceTransaction, rollbacks []Rollback) (resourceChanges, error) {
	c, state := tx.cache, tx.state
	for _, rollback := range rollbacks {
		lifecycle, ok := rollback.(*rollbackLifecycle)
		if !ok || lifecycle == nil || lifecycle.cache != c || lifecycle.nodeID != tx.nodeID {
			return resourceChanges{}, fmt.Errorf("rollback does not belong to cache node %s", tx.nodeID)
		}
	}

	// Compose predecessor chains oldest first, before preparing any changes.
	// This also rebases later caller/response inverses which are not selected:
	// their eventual rollback must not resurrect a rejected predecessor. Rejection
	// is definitive even if publishing this correction subsequently fails.
	for _, rollback := range slices.Backward(rollbacks) {
		lifecycle := rollback.(*rollbackLifecycle)
		if lifecycle.resources != nil {
			r.rebaseRejected(state, *lifecycle.resources)
		}
	}

	var changes resourceChanges
	if len(rollbacks) == 1 {
		lifecycle := rollbacks[0].(*rollbackLifecycle)
		if lifecycle.completedLocked() {
			lifecycle.warnDuplicateLocked("revert")
			return resourceChanges{}, nil
		}
		if lifecycle.resources == nil {
			changes = r.resourceRevertInverse(state, lifecycle.generation.TransactionID(), lifecycle.inverse)
		} else {
			changes = lifecycle.resources.resourceRevert(state)
		}
	} else {
		var combined rollbackResources
		for _, rollback := range rollbacks {
			lifecycle := rollback.(*rollbackLifecycle)
			if lifecycle.resources == nil {
				continue
			}
			for typeURL, entries := range *lifecycle.resources {
				for name, entry := range entries {
					if state.resources[typeURL][name].transaction != entry.expectedTransaction {
						continue
					}
					if combined[typeURL] == nil {
						combined[typeURL] = make(map[string]rollbackEntry)
					}
					combined[typeURL][name] = entry
				}
			}
		}
		changes = combined.resourceRevert(state)
	}

	return changes, nil
}

// finishRevertLocked consumes terminal callers even on failure, but retains
// failed response recovery. Caller must hold cacheImpl.mutex.
func (r *rollbackState) finishRevertLocked(state *nodeState, rollbacks []Rollback, err error) {
	for _, rollback := range rollbacks {
		lifecycle := rollback.(*rollbackLifecycle)
		if !lifecycle.completedLocked() && (err == nil || lifecycle.resources == nil) {
			// All response inverses survive a failed batch. Caller resolution
			// remains terminal even on failure, independently of response ownership.
			r.finalizeLocked(state, lifecycle)
		}
	}
}

// pruneUnownedRemovalsLocked releases removal tombstones that no response
// inverse retained. Caller-tracked removals keep their separate ownership.
func (r *rollbackState) pruneUnownedRemovalsLocked(tx *resourceTransaction, changes resourceChanges, options resourceUpdateOptions) {
	if options.tracking == responseRollbackTracking && changes.hasRemovals() {
		state := tx.state
		changedTypeURLs := changes.typeURLs()
		// Without a caller lifecycle, a removal tombstone is needed only
		// while cache-owned response rollback still references it. A
		// coalesced add/remove may leave no such rollback to release it.
		for typeURL := range changedTypeURLs.Members() {
			state.typeStates[typeURL].rollbacks.pruneInverseTombstones(typeURL, &state.resources[typeURL], options.inverse, tx.generation.TransactionID())
		}
	}
}

func (r *rollbackState) mergePending(state *nodeState, base typeurl.Map[rollbackResources], typeURLs typeurl.Set, inverse resources, transaction callbacks.TransactionID) typeurl.Map[rollbackResources] {
	if typeURLs.Empty() {
		return base
	}
	for typeURL := range typeURLs.Members() {
		rollback, _ := base.Get(typeURL)
		// A response rejects a caller transaction, not just its delivered type.
		// Keep the inverse of every changed member together. Independent API
		// transactions are still separated when a partial response is collected.
		for index := range typeurl.Indices() {
			rollback.mergeTypeURL(state, index, inverse, transaction)
		}
		// Publication may be delayed indefinitely. Bound transaction membership
		// and unobservable removal inverses against private desired state now,
		// without materializing or hashing a snapshot merely to prune history.
		rollback.pruneTransactions(state)
		rollback.pruneUnobservableResources(state, nil)
		if rollback.empty() {
			base.Remove(typeURL)
		} else {
			base.Set(typeURL, rollback)
		}
	}
	return base
}

func (r *rollbackState) releaseSet(state *nodeState, rollbacks typeurl.Map[rollbackResources]) {
	for _, rollback := range rollbacks.All() {
		r.release(state, rollback)
	}
}

// mergeHistoryMap folds a newer, independently owned rollback into an
// older unsent one. The oldest previous value remains the rollback target,
// while the newest expected transaction fences the combined rollback. Ownership
// of a superseded tombstone moves to the newer entry.
func (r *rollbackState) mergeHistoryMap(state *nodeState, typeURL typeurl.Index, older, newer map[string]rollbackEntry) map[string]rollbackEntry {
	if len(newer) == 0 {
		return older
	}
	if older == nil {
		return newer
	}
	typeState := &state.typeStates[typeURL]
	for name, newerEntry := range newer {
		if olderEntry, exists := older[name]; exists {
			newerEntry.previous = olderEntry.previous
			newerEntry.transactions.Merge(olderEntry.transactions)
			typeState.rollbacks.removeOwner(rollbackOwnerKey{name: name, transaction: olderEntry.expectedTransaction})
			if newerEntry.previousEquals(state.resources[typeURL][name].resource) {
				// The new mutation returned this name to the value preceding the
				// unsent chain. Release the newer removal tombstone as well.
				typeState.rollbacks.removeOwner(rollbackOwnerKey{name: name, transaction: newerEntry.expectedTransaction})
				delete(older, name)
				continue
			}
		}
		older[name] = newerEntry
	}
	if len(older) == 0 {
		return nil
	}
	return older
}

func (rollback rollbackResources) resourceRevert(state *nodeState) resourceChanges {
	var changes resourceChanges
	for typeURL := range typeurl.Indices() {
		current := state.resourceEntries(typeURL)
		for name, entry := range rollback[typeURL] {
			previous := current[name]
			if previous.transaction != entry.expectedTransaction {
				continue
			}
			// Rebasing a selected inverse can yield identical protobuf contents,
			// but its transaction must still be restored with a fresh revision.
			changes.add(typeURL, name, previous, entry.previous)
		}
	}
	return changes
}

func (r *rollbackState) resourceRevertInverse(state *nodeState, transaction callbacks.TransactionID, inverse resources) resourceChanges {
	var changes resourceChanges
	for typeURL := range typeurl.Indices() {
		current := state.resourceEntries(typeURL)
		for name, previous := range inverse.resources(typeURL) {
			entry := current[name]
			// The inverse only contains semantic changes made by transaction.
			// A matching transaction therefore cannot already contain previous.
			if entry.transaction != transaction {
				continue
			}
			changes.add(typeURL, name, entry, previous)
		}
	}
	return changes
}

// rebaseRejected bypasses rejected values in every live inverse before
// releasing their response owner. A newer value must remain transaction-fenced,
// but reverting it later must not restore its rejected predecessor. Selected
// inverses remain indexed until the complete NACK batch has been applied;
// rebasing them oldest first composes their targets without exposing intermediate
// desired states.
// Only inverse targets change; expected transactions and tombstone ownership do
// not. No rejection history survives beyond these live inverses.
// Caller must hold cacheImpl.mutex.
func (r *rollbackState) rebaseRejected(state *nodeState, rejected rollbackResources) {
	// Unpublished inverses have no lifecycle yet, but their future responses
	// must also bypass rejected predecessors. Change only inverse targets:
	// transaction guards and pending-publication ownership remain unchanged.
	if pending := state.pendingPublication; pending != nil {
		for _, rollback := range pending.rollbacks.All() {
			rollback.rebaseRejected(rejected)
		}
	}
	for lifecycle := range r.responses.Members() {
		lifecycle.resources.rebaseRejected(rejected)
	}
	for lifecycle := range r.callers.Members() {
		inverse := &lifecycle.inverse
		if inverse.hasSingleton() {
			singleton := &inverse.singleton
			entry, exists := rejected[singleton.typeURL][singleton.name]
			if exists && singleton.entry.transaction == entry.expectedTransaction {
				singleton.entry = entry.previous
			}
			continue
		}
		for typeURL, entries := range rejected {
			for name, entry := range entries {
				previous, exists := inverse.entries[typeURL][name]
				if exists && previous.transaction == entry.expectedTransaction {
					inverse.entries[typeURL][name] = entry.previous
				}
			}
		}
	}
}

func (r *rollbackState) updateOwners(state *nodeState, rollback rollbackResources, delta int) {
	for typeURL := range typeurl.Indices() {
		state.typeStates[typeURL].rollbacks.updateOwnerMap(rollback[typeURL], delta)
	}
}

func (r *rollbackState) updateInverseOwners(state *nodeState, inverse resources, transaction callbacks.TransactionID, delta int) {
	for typeURL := range typeurl.Indices() {
		state.typeStates[typeURL].rollbacks.updateInverseOwnerMap(typeURL, state.resources[typeURL], inverse, transaction, delta)
	}
}

func (r *rollbackState) release(state *nodeState, rollback rollbackResources) {
	r.updateOwners(state, rollback, -1)
	for typeURL := range typeurl.Indices() {
		state.typeStates[typeURL].rollbacks.pruneReleasedTombstones(&state.resources[typeURL], rollback[typeURL])
	}
}

func (r *rollbackState) releaseInverse(state *nodeState, inverse resources, transaction callbacks.TransactionID) {
	r.updateInverseOwners(state, inverse, transaction, -1)
	for typeURL := range typeurl.Indices() {
		state.typeStates[typeURL].rollbacks.pruneInverseTombstones(typeURL, &state.resources[typeURL], inverse, transaction)
	}
}

// resourceStateIsObservable reports whether a SotW response can communicate a
// resource's presence or removal. It uses the published snapshot when available,
// or the desired state before publication.
func (r *rollbackState) resourceStateIsObservable(state *nodeState, snapshot cache.ResourceSnapshot, index typeurl.Index, name string) bool {
	if snapshot != nil {
		return callbacks.SnapshotResourceStateIsObservable(snapshot, index, name)
	}
	switch index {
	case typeurl.Listener, typeurl.Cluster, typeurl.NetworkPolicy, typeurl.NetworkPolicyHosts:
		return true // SotW omission can convey a removal for these types.
	case typeurl.Endpoint:
		if state.resources[index][name].resource != nil {
			return true
		}
		// Removing a referenced CLA publishes a named empty assignment, not
		// an omission. Keep its inverse before that projection is constructed.
		if state.strictRefs != nil {
			return state.strictRefs.endpoints[name] > 0
		}
		for clusterName, entry := range state.resources[typeurl.Cluster] {
			if clusterEndpointName(clusterName, typedResource[*cluster.Cluster](entry.resource)) == name {
				return true
			}
		}
		return false
	default:
		return state.resources[index][name].resource != nil
	}
}

func (r *rollbackState) acquireSet(state *nodeState, rollbacks typeurl.Map[rollbackResources]) {
	for _, rollback := range rollbacks.All() {
		r.updateOwners(state, rollback, 1)
	}
}

func (state *resourceRollbackState) ownerCount(key rollbackOwnerKey) uint32 {
	return state.owners[key]
}

func (state *resourceRollbackState) addOwner(key rollbackOwnerKey) {
	if state.owners == nil {
		state.owners = make(map[rollbackOwnerKey]uint32)
	}
	state.owners[key]++
}

func (state *resourceRollbackState) removeOwner(key rollbackOwnerKey) {
	owners := state.owners
	count := owners[key]
	if count > 1 {
		owners[key] = count - 1
		return
	}
	delete(owners, key)
	if len(owners) == 0 {
		state.owners = nil
	}
}

func (state *resourceRollbackState) updateOwnerMap(resources map[string]rollbackEntry, delta int) {
	if len(resources) == 0 {
		return
	}
	for name, entry := range resources {
		key := rollbackOwnerKey{name: name, transaction: entry.expectedTransaction}
		if delta > 0 {
			state.addOwner(key)
			continue
		}
		state.removeOwner(key)
	}
}

func (state *resourceRollbackState) updateInverseOwnerMap(typeURL typeurl.Index, desired map[string]resourceEntry, inverse resources, transaction callbacks.TransactionID, delta int) {
	update := func(name string) {
		key := rollbackOwnerKey{name: name, transaction: transaction}
		if delta > 0 {
			if desired[name].resource == nil {
				state.addOwner(key)
			}
		} else {
			state.removeOwner(key)
		}
	}
	for name := range inverse.resources(typeURL) {
		update(name)
	}
}

func (state *resourceRollbackState) pruneReleasedTombstones(resources *map[string]resourceEntry, rollback map[string]rollbackEntry) {
	for name, rollbackEntry := range rollback {
		entry := (*resources)[name]
		if entry.resource != nil || entry.transaction != rollbackEntry.expectedTransaction {
			continue
		}
		key := rollbackOwnerKey{name: name, transaction: entry.transaction}
		if state.ownerCount(key) == 0 {
			delete(*resources, name)
		}
	}
	if len(*resources) == 0 {
		*resources = nil
	}
}

func (state *resourceRollbackState) pruneInverseTombstones(typeURL typeurl.Index, resources *map[string]resourceEntry, inverse resources, transaction callbacks.TransactionID) {
	prune := func(name string) {
		entry := (*resources)[name]
		if entry.resource != nil || entry.transaction != transaction {
			return
		}
		key := rollbackOwnerKey{name: name, transaction: transaction}
		if state.ownerCount(key) == 0 {
			delete(*resources, name)
		}
	}
	for name := range inverse.resources(typeURL) {
		prune(name)
	}
	if len(*resources) == 0 {
		*resources = nil
	}
}

func (entry rollbackEntry) previousEquals(resource cache_types.Resource) bool {
	previous := entry.previous.resource
	return previous == resource ||
		(previous != nil && resource != nil && xds.ResourceEqual(previous, resource))
}

func (rollback rollbackResources) empty() bool {
	for typeURL := range typeurl.Indices() {
		if len(rollback[typeURL]) != 0 {
			return false
		}
	}
	return true
}

func (rollback *rollbackResources) mergeTypeURL(state *nodeState, typeURL typeurl.Index, inverse resources, transaction callbacks.TransactionID) {
	current := rollback[typeURL]
	desired := state.resources[typeURL]
	typeState := &state.typeStates[typeURL]

	if inverse.len(typeURL) == 0 {
		return
	}
	if current == nil {
		current = make(map[string]rollbackEntry, inverse.len(typeURL))
	}
	merge := func(name string, previous resourceEntry) {
		entry, exists := current[name]
		if !exists {
			entry.previous = previous
		}
		// Only an unsent rollback can be coalesced away. No response has
		// exposed any intermediate value, so returning to the original value
		// leaves nothing for a later NACK to restore.
		if exists && entry.previousEquals(desired[name].resource) {
			typeState.rollbacks.removeOwner(rollbackOwnerKey{name: name, transaction: entry.expectedTransaction})
			delete(current, name)
			return
		}
		if desired[name].resource == nil {
			typeState.rollbacks.addOwner(rollbackOwnerKey{name: name, transaction: transaction})
		}
		if exists {
			typeState.rollbacks.removeOwner(rollbackOwnerKey{name: name, transaction: entry.expectedTransaction})
		}
		entry.expectedTransaction = transaction
		if !inverse.hasSingleton() {
			entry.transactions.Insert(transaction)
		}
		current[name] = entry
	}
	for name, previous := range inverse.resources(typeURL) {
		merge(name, previous)
	}
	if len(current) == 0 {
		current = nil
	}
	rollback[typeURL] = current
}

func (rollback rollbackResources) mergeHistory(state *nodeState, newer rollbackResources) rollbackResources {
	for typeURL := range typeurl.Indices() {
		rollback[typeURL] = state.rollbacks.mergeHistoryMap(state, typeURL, rollback[typeURL], newer[typeURL])
	}
	return rollback
}

// liveTransactionIDs includes observable current members, so pruning cannot
// sever a live relationship.
func (rollback rollbackResources) liveTransactionIDs(state *nodeState, snapshot cache.ResourceSnapshot) set.Set[callbacks.TransactionID] {
	var live set.Set[callbacks.TransactionID]
	for index, entries := range rollback {
		for name, entry := range entries {
			if state.resources[index][name].transaction == entry.expectedTransaction && state.rollbacks.resourceStateIsObservable(state, snapshot, typeurl.Index(index), name) {
				live.Insert(entry.expectedTransaction)
			}
		}
	}
	return live
}

// pruneTransactions removes obsolete membership without collecting a result
// set. Superseded transactions no longer couple their former members, while
// their coalesced resource inverses still retain the rollback baseline.
func (rollback rollbackResources) pruneTransactions(state *nodeState) {
	if !rollback.hasTransactions() {
		return
	}
	live := rollback.liveTransactionIDs(state, nil)
	for _, entries := range rollback {
		for name, entry := range entries {
			var retained set.Set[callbacks.TransactionID]
			for transaction := range entry.transactions.Members() {
				if live.Has(transaction) {
					retained.Insert(transaction)
				}
			}
			entry.transactions = retained
			entries[name] = entry
		}
	}
}

// transactionIDs prunes obsolete membership and returns the remaining IDs for
// completion association. Collect in the same pass to avoid another traversal.
func (rollback rollbackResources) transactionIDs(state *nodeState, snapshot cache.ResourceSnapshot) set.Set[callbacks.TransactionID] {
	if !rollback.hasTransactions() {
		return set.Set[callbacks.TransactionID]{}
	}
	live := rollback.liveTransactionIDs(state, snapshot)
	var transactions set.Set[callbacks.TransactionID]
	for _, entries := range rollback {
		for name, entry := range entries {
			var retained set.Set[callbacks.TransactionID]
			for transaction := range entry.transactions.Members() {
				if live.Has(transaction) {
					retained.Insert(transaction)
					transactions.Insert(transaction)
				}
			}
			entry.transactions = retained
			entries[name] = entry
		}
	}
	return transactions
}

// Unobservable changes need no response inverse unless another still-live
// member of that same transaction can reject them. Caller inverses are owned
// separately. In particular, independent EDS/RDS/SDS removals must not collect
// behind an unrelated, unrequested positive resource of the same type.
func (rollback rollbackResources) pruneUnobservableResources(state *nodeState, snapshot cache.ResourceSnapshot) {
	for index := range typeurl.Indices() {
		typeState := &state.typeStates[index]
		for name, entry := range rollback[index] {
			if state.rollbacks.resourceStateIsObservable(state, snapshot, index, name) || entry.transactions.Has(entry.expectedTransaction) {
				continue
			}
			typeState.rollbacks.removeOwner(rollbackOwnerKey{name: name, transaction: entry.expectedTransaction})
			delete(rollback[index], name)
			current := state.resources[index][name]
			if current.resource == nil && current.transaction == entry.expectedTransaction && typeState.rollbacks.ownerCount(rollbackOwnerKey{name: name, transaction: current.transaction}) == 0 {
				delete(state.resources[index], name)
			}
		}
	}
}

func (rollback rollbackResources) hasTransactions() bool {
	for _, entries := range rollback {
		for _, entry := range entries {
			if !entry.transactions.Empty() {
				return true
			}
		}
	}
	return false
}

func (rollback rollbackResources) rebaseRejected(rejected rollbackResources) {
	for typeURL, entries := range rejected {
		for name, rejectedEntry := range entries {
			entry, exists := rollback[typeURL][name]
			if exists && entry.previous.transaction == rejectedEntry.expectedTransaction {
				entry.previous = rejectedEntry.previous
				rollback[typeURL][name] = entry
			}
		}
	}
}

func (rollback rollbackResources) hasObservableResources(snapshot cache.ResourceSnapshot, index typeurl.Index) bool {
	for name := range rollback[index] {
		if callbacks.SnapshotResourceStateIsObservable(snapshot, index, name) {
			return true
		}
	}
	return false
}

// clone copies every map in an unpublished rollback, including its transaction's
// changes to other resource types.
func (rollback rollbackResources) clone() rollbackResources {
	for typeURL := range typeurl.Indices() {
		rollback[typeURL] = maps.Clone(rollback[typeURL])
		// Membership sets may themselves own mutable maps after several bulk
		// transactions coalesce. A failed publication must restore those too.
		for name, entry := range rollback[typeURL] {
			entry.transactions = entry.transactions.Clone()
			rollback[typeURL][name] = entry
		}
	}
	return rollback
}

func clonePendingRollbacks(rollbacks typeurl.Map[rollbackResources]) typeurl.Map[rollbackResources] {
	var cloned typeurl.Map[rollbackResources]
	for typeURL, rollback := range rollbacks.All() {
		cloned.Set(typeURL, rollback.clone())
	}
	return cloned
}

func (lifecycle *rollbackLifecycle) resourceScope(response cache.Response) *callbacks.ResourceScope {
	var scope *callbacks.ResourceScope
	if lifecycle.resources != nil {
		for name, entry := range (*lifecycle.resources)[lifecycle.typeURL] {
			if callbacks.ResourceStateIsObservable(response, name) {
				if scope == nil {
					scope = &callbacks.ResourceScope{}
				}
				// A response inverse is actionable from its originating API
				// transaction onward; caller waits require the current revision.
				scope.Insert(name, entry.expectedTransaction.InitialRevision())
			}
		}
	}
	return scope
}

func (lifecycle *rollbackLifecycle) warnDuplicateLocked(action string) {
	lifecycle.cache.logger.Warn("Ignoring duplicate resource update rollback resolution",
		logfields.NodeID, lifecycle.nodeID,
		logfields.XDSRollbackGeneration, lifecycle.generation,
		logfields.Operation, action)
}

// completedLocked reports whether finalization or reversion has consumed the
// lifecycle's rollback payload. Caller must hold cacheImpl.mutex.
func (lifecycle *rollbackLifecycle) completedLocked() bool {
	return lifecycle.resources == nil && lifecycle.inverse.empty()
}
