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

// rollbackState owns the node's live caller/response lifecycles and maintains
// their transaction dependencies. Methods borrow node or transaction context
// for desired resources and publication; they never take the cache lock or
// invoke user callbacks. All access requires cacheImpl.mutex.
type rollbackState struct {
	// Response outcome releases these inverses independently of caller lifetime.
	responses set.Set[*rollbackLifecycle]
	// Caller resolution is terminal; these are live inverses, not history.
	callers set.Set[*rollbackLifecycle]
	// dependents indexes only response-owned dependent entries, not
	// ordinary inverses or strict ADS protobuf references. A name retains every
	// owner until that entry is removed, partitioned, or its lifecycle resolves.
	// Pending-publication dependencies have no lifecycle yet and stay separate.
	dependents typeurl.Map[map[string]set.Set[*rollbackLifecycle]]
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
	cache  *cacheImpl
	ctx    context.Context
	nodeID string
	// Response-type entries are the triggering resource changes, not separate
	// transactions. Other entries can belong to those same API transactions.
	// Caller lifecycles use typeurl.Count because they are not response-specific.
	typeURL typeurl.Index
	// generation is the response inverse's boundary. For a caller inverse
	// (resources == nil), it stores the original API transaction's generation;
	// only that case converts it back to a TransactionID for the revert guard.
	generation callbacks.Generation
	resources  *rollbackResources
	// dependents retains coalesced inverses of later transactions using values
	// still owned by this response, independently of their caller lifetimes.
	dependents *rollbackResources
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
	// Original inverses retain live transaction membership and prerequisite
	// identities through coalescing. Dependent inverses use the same set for
	// their prerequisite transaction IDs, allowing named-response splits.
	transactions set.Set[callbacks.TransactionID]
}

type rollbackResources typeurl.Slots[map[string]rollbackEntry]

// insertDependentRollback indexes a dependent name. Sets are stored by value,
// so persist their header when insertion changes the singleton representation.
func (r *rollbackState) insertDependentRollback(lifecycle *rollbackLifecycle, typeURL typeurl.Index, name string) {
	owners, _ := r.dependents.Get(typeURL)
	lifecycles := owners[name]
	if lifecycles.Has(lifecycle) {
		return
	}
	if owners == nil {
		owners = make(map[string]set.Set[*rollbackLifecycle])
		r.dependents.Set(typeURL, owners)
	}
	lifecycles.Insert(lifecycle)
	owners[name] = lifecycles
}

// removeDependentRollback persists the updated set header and releases empty
// name/type entries immediately, so the index cannot retain completed owners.
func (r *rollbackState) removeDependentRollback(lifecycle *rollbackLifecycle, typeURL typeurl.Index, name string) {
	owners, _ := r.dependents.Get(typeURL)
	lifecycles := owners[name]
	lifecycles.Remove(lifecycle)
	if lifecycles.Empty() {
		delete(owners, name)
	} else {
		owners[name] = lifecycles
	}
	if len(owners) == 0 {
		r.dependents.Remove(typeURL)
	}
}

// Index changes share the cache lock with payload changes. Coalescing and
// partitioning may replace arbitrary dependent names; unindex before changing
// their maps and reindex before consulting live transaction membership.
func (r *rollbackState) indexDependents(lifecycle *rollbackLifecycle) {
	if lifecycle.dependents == nil {
		return
	}
	for typeURL, entries := range *lifecycle.dependents {
		for name := range entries {
			r.insertDependentRollback(lifecycle, typeurl.Index(typeURL), name)
		}
	}
}

func (r *rollbackState) unindexDependents(lifecycle *rollbackLifecycle) {
	if lifecycle.dependents == nil {
		return
	}
	for typeURL, entries := range *lifecycle.dependents {
		for name := range entries {
			r.removeDependentRollback(lifecycle, typeurl.Index(typeURL), name)
		}
	}
}

// prepareDependenciesLocked captures reused pending values before mutation.
// Dependency attachment waits until commit/publication succeeds, so failure
// cannot leave another response owning the rejected update's inverse.
// Return scratch scopes by value so extracting this step does not force them
// onto the heap; the caller borrows their address only while holding the lock.
func (r *rollbackState) prepareDependenciesLocked(tx *resourceTransaction, mutations *ResourceMutations, inverse *resources, changedNames int, wait bool) (reused reusedResources, scopes typeurl.Map[callbacks.ResourceScope]) {
	state := tx.state
	// All-changed updates cannot depend on values reused unchanged. Avoid even
	// the collection pass on that common path; overlaps between removals and
	// upserts merely make this conservative count trigger an unnecessary scan.
	removed, upserted := &mutations.Removed, &mutations.Upserted
	names := len(removed.Listeners) + len(upserted.Listeners) +
		len(removed.Routes) + len(upserted.Routes) +
		len(removed.Clusters) + len(upserted.Clusters) +
		len(removed.Endpoints) + len(upserted.Endpoints) +
		len(removed.Secrets) + len(upserted.Secrets)
	if names > changedNames &&
		(!r.responses.Empty() || state.pendingPublication != nil && !state.pendingPublication.rollbacks.Empty()) {
		reused = r.unchangedResources(state, mutations, inverse, names-changedNames-1)
	}
	var dependencies *typeurl.Map[callbacks.ResourceScope]
	if wait && reused.first.name != "" {
		dependencies = &scopes
	}
	tx.dependencyTransactions = r.pendingDependencies(state, &reused, dependencies)

	return reused, scopes
}

// attachDependenciesLocked runs only after successful commit/publication.
// Resolve current owners here because publication may partition them.
func (r *rollbackState) attachDependenciesLocked(tx *resourceTransaction, reused reusedResources, inverse resources, dependencies *typeurl.Map[callbacks.ResourceScope]) {
	c := tx.cache
	if reused.first.name != "" {
		for response := range r.responses.Members() {
			prerequisites := response.resources.dependencyTransactions(&reused, response.typeURL, response.dependents)
			if prerequisites.Empty() {
				continue
			}
			response.resources.addDependencyScope(tx.state, response.typeURL, prerequisites, dependencies)
			response.retainDependentTransactionLocked(tx.state, inverse, tx.generation.TransactionID(), prerequisites)
		}
	}
	if dependencies != nil && !dependencies.Empty() {
		for comp := range tx.registeredCompletions.Members() {
			c.completionCbs.AddCompletionDependencies(comp, *dependencies)
		}
	}
}

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
	var dependents *typeurl.Map[rollbackResources]
	if oldPending != nil {
		oldPendingValue = *oldPending
		mergedTypeURLs = oldPending.changedTypeURLs.Union(dirtyTypeURLs)
		watchTypeURLs = oldPending.watchTypeURLs.Union(watchTypeURLs)
		rollbacks = oldPending.rollbacks
		dependents = oldPending.dependents
	}
	willFinalize = state.hasOpenWatchLocked(watchTypeURLs)
	if willFinalize && oldPending != nil {
		// Only publication can fail after resources have been committed. Keep a
		// defensive copy for that rare path without cloning unpublished rollback
		// maps on every ordinary mutation.
		oldPendingValue.rollbacks = clonePendingRollbacks(oldPending.rollbacks)
		if oldPending.dependents != nil {
			cloned := clonePendingRollbacks(*oldPending.dependents)
			oldPendingValue.dependents = &cloned
		}
	}
	if options.tracking != noRollbackTracking {
		rollbacks = r.mergePending(state, rollbacks, changedTypeURLs, options.inverse, tx.generation.TransactionID())
		if tx.dependencyTransactions != nil {
			for typeURL, prerequisites := range tx.dependencyTransactions.All() {
				if dependents == nil {
					dependents = new(typeurl.Map[rollbackResources])
				}
				rollback, _ := dependents.Get(typeURL)
				triggeringChanges, _ := rollbacks.Get(typeURL)
				triggeringChanges.markPrerequisites(prerequisites)
				rollback = rollback.mergeDependentTransaction(state, triggeringChanges, options.inverse, tx.generation.TransactionID(), prerequisites)
				if rollback.empty() {
					dependents.Remove(typeURL)
				} else {
					dependents.Set(typeURL, rollback)
				}
			}
		}
	}
	if dependents != nil {
		for typeURL := range dependents.Keys() {
			rollback, _ := dependents.Get(typeURL)
			triggeringChanges, _ := rollbacks.Get(typeURL)
			triggeringChanges.normalizeDependencies(state, typeURL, &rollback)
			if rollback.empty() || triggeringChanges.empty() {
				// An unsent prerequisite which coalesces to a net no-op cannot
				// be NACKed. An entry which only binds versions has no triggering
				// resource changes, so release its dependent ownership as well.
				r.release(state, rollback)
				dependents.Remove(typeURL)
			}
		}
		if dependents.Empty() {
			dependents = nil
		}
	}
	// Add entries which only bind versions after building rollback state, which
	// omits empty values. Preserve existing rollback state for the same type.
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
		dependents:      dependents,
	}
	state.pendingPublication = pending
	// Normalize dependencies before pruning membership: an old unsent identity
	// must not keep itself alive through a dependent's historical tags. Neither
	// step needs a snapshot while Envoy has no watch ready for these updates.
	// Iterate keys, not All: escaping the iterator's captured array adds a
	// large temporary allocation to every otherwise cheap mutation.
	for typeURL := range rollbacks.Keys() {
		rollback, _ := rollbacks.Get(typeURL)
		rollback.pruneTransactions(state)
		rollback.pruneUnobservableResources(state, nil)
	}

	return oldPending, oldPendingValue, willFinalize
}

// restorePublicationLocked reacquires saved ownership before releasing the
// failed replacement, so shared tombstones remain continuously guarded.
func (r *rollbackState) restorePublicationLocked(state *nodeState, oldPending *pendingPublication, oldPendingValue pendingPublication) {
	if oldPending != nil {
		r.acquireSet(state, oldPendingValue.rollbacks)
		if oldPendingValue.dependents != nil {
			r.acquireSet(state, *oldPendingValue.dependents)
		}
	}
	r.releaseSet(state, state.pendingPublication.rollbacks)
	if state.pendingPublication.dependents != nil {
		r.releaseSet(state, *state.pendingPublication.dependents)
	}
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
		var dependents rollbackResources
		if pending.dependents != nil {
			dependents, _ = pending.dependents.Get(typeURL)
		}
		if rollback.empty() {
			continue
		}
		versionChanged := oldSnapshot == nil ||
			oldSnapshot.GetVersion(typeURL.URL()) != newSnapshot.GetVersion(typeURL.URL())
		if !versionChanged {
			r.release(state, rollback)
			r.release(state, dependents)
			continue
		}
		r.retainUnsentLocked(c, state, typeURL, pending.generation, rollback, dependents, newSnapshot)
	}
}

// retainUnsentLocked keeps one coalesced rollback for a resource type
// until go-control-plane produces a response carrying the current version.
// Register it before delivery so the response can acquire its inverse even
// when the caller supplied no WaitGroup. A reconnecting client's echoed version
// alone cannot prove which names it received; retain the inverse until an
// actual response establishes acceptance or rejection.
func (r *rollbackState) retainUnsentLocked(c *cacheImpl, state *nodeState, typeURL typeurl.Index, generation callbacks.Generation, rollback, dependents rollbackResources, snapshot cache.ResourceSnapshot) {
	nodeID := state.nodeID
	if existing := state.typeStates[typeURL].rollbacks.unsent; existing != nil && !existing.completedLocked() {
		if c.completionCbs.CoalesceUnsentTypeGeneration(nodeID, typeURL, existing.generation, generation, nil) {
			r.unindexDependents(existing)
			*existing.resources = existing.resources.mergeHistory(state, rollback)
			if !dependents.empty() {
				if existing.dependents == nil {
					existing.dependents = new(rollbackResources)
					*existing.dependents = dependents
				} else {
					for index := range typeurl.Indices() {
						existing.dependents[index] = r.mergeHistoryMap(state, index,
							existing.dependents[index], dependents[index], existing.resources[index])
					}
				}
			}
			existing.resources.normalizeDependencies(state, typeURL, existing.dependents)
			if existing.dependents != nil && existing.dependents.empty() {
				existing.dependents = nil
			}
			r.indexDependents(existing)
			if existing.resources.hasTransactions() || existing.dependents != nil {
				c.completionCbs.SetGenerationTransactions(nodeID, typeURL, generation, existing.transactionIDs(state, snapshot))
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
		r.release(state, dependents)
		return
	}

	// Response rollback must outlive the context of the mutation which created
	// it. A later NACK remains actionable after that caller has timed out.
	lifecycle := r.newResponseLocked(c, state, typeURL, generation, rollback)
	if !dependents.empty() {
		lifecycle.dependents = new(rollbackResources)
		*lifecycle.dependents = dependents
		r.indexDependents(lifecycle)
	}
	c.completionCbs.AddTypeGenerationWithRollback(generation, typeURL, nodeID, lifecycle, nil)
	state.typeStates[typeURL].rollbacks.unsent = lifecycle
	if rollback.hasTransactions() || lifecycle.dependents != nil {
		c.completionCbs.SetGenerationTransactions(nodeID, typeURL, generation, lifecycle.transactionIDs(state, snapshot))
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
	if lifecycle.dependents != nil {
		r.unindexDependents(lifecycle)
		dependents := lifecycle.dependents.partitionDependents(state, selected)
		if !dependents.empty() {
			sentLifecycle.dependents = &dependents
		}
		if lifecycle.dependents.empty() {
			lifecycle.dependents = nil
		}
		r.indexDependents(lifecycle)
		r.indexDependents(sentLifecycle)
	}
	sentScope := sentLifecycle.resourceScope(response)
	c.completionCbs.PartitionUnsentTypeGeneration(nodeID, typeURL, oldGeneration,
		remainingGeneration, lifecycle, nil, sentGeneration, sentLifecycle, sentScope)
	snapshot, _ := c.SnapshotCache.GetSnapshot(nodeID)
	c.completionCbs.SetGenerationTransactions(nodeID, typeURL, remainingGeneration, lifecycle.transactionIDs(state, snapshot))
	c.completionCbs.SetGenerationTransactions(nodeID, typeURL, sentGeneration, sentLifecycle.transactionIDs(state, snapshot))
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
// payload on failure so a later NACK can retry recovery. Committing unpublished
// changes makes the compensation effective without waiting for a response.
// Caller must hold cacheImpl.mutex.
func (r *rollbackState) finalizeLocked(state *nodeState, lifecycle *rollbackLifecycle) {
	if lifecycle.completedLocked() {
		lifecycle.warnDuplicateLocked("finalize")
		return
	}
	responseResources, dependents, inverse := lifecycle.resources, lifecycle.dependents, lifecycle.inverse
	r.unindexDependents(lifecycle)
	lifecycle.resources = nil
	lifecycle.dependents = nil
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
	if dependents != nil {
		r.release(state, *dependents)
	}
	if r.hasDependents(state) {
		for typeURL := range typeurl.Indices() {
			for name := range inverse.resources(typeURL) {
				r.pruneAbsentDependentResource(state, typeURL, name)
			}
			if responseResources != nil {
				for name := range responseResources[typeURL] {
					r.pruneAbsentDependentResource(state, typeURL, name)
				}
			}
			if dependents != nil {
				for name := range dependents[typeURL] {
					r.pruneAbsentDependentResource(state, typeURL, name)
				}
			}
		}
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

// Revert restores caller-owned state after an enclosing failure, or response-
// owned state after a NACK. Transaction IDs fence ordinary reverts; response
// recovery also undoes dependent transactions in either ADS mode and expands
// references only to maintain strict ADS consistency. Restoring a previous
// value restores its transaction identity but assigns a fresh revision, so old
// ACKs cannot accept corrected state. Published snapshots remain immutable.
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
	var haveTransactionMembers bool
	for _, rollback := range rollbacks {
		lifecycle, ok := rollback.(*rollbackLifecycle)
		if !ok || lifecycle == nil || lifecycle.cache != c || lifecycle.nodeID != tx.nodeID {
			return resourceChanges{}, fmt.Errorf("rollback does not belong to cache node %s", tx.nodeID)
		}
		if lifecycle.resources != nil && !haveTransactionMembers {
			for typeURL, entries := range *lifecycle.resources {
				if typeurl.Index(typeURL) != lifecycle.typeURL && len(entries) != 0 {
					haveTransactionMembers = true
					break
				}
			}
		}
	}

	if len(rollbacks) == 1 && rollbacks[0].(*rollbackLifecycle).resources == nil {
		lifecycle := rollbacks[0].(*rollbackLifecycle)
		if lifecycle.completedLocked() {
			lifecycle.warnDuplicateLocked("revert")
			return resourceChanges{}, nil
		}
		return r.resourceRevertInverse(state, lifecycle.generation.TransactionID(), lifecycle.inverse), nil
	}

	// A triggering resource change belongs to the NACKed TypeURL. Match its
	// name across the batch so an older selected change can participate when a
	// newer selected change replaced it. An independently superseding value
	// must not make other members of that original transaction eligible.
	var eligibleTransactions set.Set[callbacks.TransactionID]
	if haveTransactionMembers {
		// Single-type inverses, notably NPDS, need only their existing transaction
		// guards. Do not build eligibility sets unless other-type members exist.
		var activeTriggeringChanges typeurl.Slots[set.Set[string]]
		for _, rollback := range rollbacks {
			lifecycle := rollback.(*rollbackLifecycle)
			if lifecycle.resources == nil {
				continue
			}
			for name, entry := range (*lifecycle.resources)[lifecycle.typeURL] {
				if lifecycle.dependents != nil {
					if dependent, exists := lifecycle.dependents[lifecycle.typeURL][name]; exists {
						entry = dependent
					}
				}
				if state.resources[lifecycle.typeURL][name].transaction == entry.expectedTransaction {
					activeTriggeringChanges[lifecycle.typeURL].Insert(name)
				}
			}
		}
		for _, rollback := range rollbacks {
			lifecycle := rollback.(*rollbackLifecycle)
			if lifecycle.resources == nil {
				continue
			}
			for name, entry := range (*lifecycle.resources)[lifecycle.typeURL] {
				if activeTriggeringChanges[lifecycle.typeURL].Has(name) {
					eligibleTransactions.Insert(entry.expectedTransaction)
					// Coalesced predecessors can still own distinct transaction members.
					eligibleTransactions.Merge(entry.transactions)
				}
			}
		}
	}

	// Compose rejected predecessor chains oldest first. Other-type transaction
	// members whose triggering changes were superseded are not rejected: neither
	// revert them nor bypass them in a later caller/response inverse. Directly
	// NACKed changes still need rebasing even when their current value is newer.
	for _, rollback := range slices.Backward(rollbacks) {
		lifecycle := rollback.(*rollbackLifecycle)
		if lifecycle.resources != nil {
			r.rebaseRejected(state, *lifecycle.resources, lifecycle.typeURL, eligibleTransactions)
			if lifecycle.dependents != nil {
				r.rebaseRejected(state, *lifecycle.dependents, typeurl.Count, set.Set[callbacks.TransactionID]{})
			}
		}
	}

	var changes resourceChanges
	var combined rollbackResources
	for _, rollback := range rollbacks {
		lifecycle := rollback.(*rollbackLifecycle)
		if lifecycle.resources == nil {
			continue
		}
		resources := lifecycle.resources.withDependents(lifecycle.dependents)
		prepared := resources.resourceRevert(state, lifecycle.typeURL, eligibleTransactions)
		if lifecycle.dependents != nil {
			for typeURL, entries := range *lifecycle.dependents {
				for name, entry := range entries {
					current := state.resources[typeURL][name]
					if current.transaction != entry.expectedTransaction {
						continue
					}
					// A superseded prerequisite does not protect B's still-current
					// dependent value. Use the composed target, including any
					// rejected predecessors already bypassed above.
					prepared.set(typeurl.Index(typeURL), name, current, resources[typeURL][name].previous)
				}
			}
		}
		if len(rollbacks) == 1 {
			changes, combined = prepared, resources
			break
		}
		if !prepared.empty() {
			change := prepared.first
			changes.set(change.typeURL, change.name, change.previous, change.next)
		}
		for _, change := range prepared.more {
			changes.set(change.typeURL, change.name, change.previous, change.next)
		}
		if c.strictAdsMode {
			// Keep fallback targets for reference closure, but never expose
			// intermediate corrections or validate them independently.
			for typeURL, entries := range resources {
				for name, entry := range entries {
					if combined[typeURL] == nil {
						combined[typeURL] = make(map[string]rollbackEntry)
					}
					combined[typeURL][name] = entry
				}
			}
		}
	}
	// Transaction dependencies apply in both modes. Only strict ADS expands
	// the complete batch to otherwise unrelated resources for consistency.
	if c.strictAdsMode && changes.affectsStrictConsistency() {
		r.completeStrictResourceRevert(state, &changes, combined)
	}

	return changes, nil
}

// finishRevertLocked consumes terminal callers even on failure, but retains
// failed response recovery. Successful correction can also prune dependencies.
func (r *rollbackState) finishRevertLocked(state *nodeState, rollbacks []Rollback, changes resourceChanges, err error) {
	for _, rollback := range rollbacks {
		lifecycle := rollback.(*rollbackLifecycle)
		if !lifecycle.completedLocked() && (err == nil || lifecycle.resources == nil) {
			// All response inverses survive a failed batch. Caller resolution
			// remains terminal even on failure, independently of response ownership.
			r.finalizeLocked(state, lifecycle)
		}
	}

	if err == nil {
		r.pruneAbsentDependentChanges(state, changes)
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
func (r *rollbackState) mergeHistoryMap(state *nodeState, typeURL typeurl.Index, older, newer, aliases map[string]rollbackEntry) map[string]rollbackEntry {
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
			alias, aliased := aliases[name]
			if newerEntry.previousEquals(state.resources[typeURL][name].resource) &&
				!(aliased && alias.expectedTransaction == newerEntry.previous.transaction) {
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

// resourceRevert selects transaction-fenced rollback in either ADS mode. Other-
// type members require an eligible triggering resource change in their own
// transaction; sharing a coalesced response is not enough. Strict reference
// recovery is a separate step after this selection.
func (rollback rollbackResources) resourceRevert(state *nodeState, triggeringType typeurl.Index, transactions set.Set[callbacks.TransactionID]) resourceChanges {
	var changes resourceChanges
	// Restore every still-current member of the rejected transaction first.
	// Reference consistency must not suppress a content rollback merely because
	// the restored parent continues to refer to the same child.
	for typeURL, entries := range rollback {
		index := typeurl.Index(typeURL)
		for name, entry := range entries {
			if index != triggeringType && !transactions.Has(entry.expectedTransaction) {
				continue
			}
			previous := state.resources[index][name]
			if previous.transaction == entry.expectedTransaction {
				// Rebasing can restore identical protobuf contents, but the original
				// transaction must still be restored with a fresh revision.
				changes.add(index, name, previous, entry.previous)
			}
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
// triggeringType == typeurl.Count denotes dependent changes, all of which were
// rejected through their prerequisite; ordinary members require eligibility.
// Caller must hold cacheImpl.mutex.
func (r *rollbackState) rebaseRejected(state *nodeState, rejected rollbackResources, triggeringType typeurl.Index, transactions set.Set[callbacks.TransactionID]) {
	// Unpublished inverses have no lifecycle yet, but their future responses
	// must also bypass rejected predecessors. Change only inverse targets:
	// transaction guards and pending-publication ownership remain unchanged.
	if pending := state.pendingPublication; pending != nil {
		for _, rollback := range pending.rollbacks.All() {
			rollback.rebaseRejected(rejected, triggeringType, transactions)
		}
		if pending.dependents != nil {
			for _, dependents := range pending.dependents.All() {
				dependents.rebaseRejected(rejected, triggeringType, transactions)
			}
		}
	}
	for lifecycle := range r.responses.Members() {
		lifecycle.resources.rebaseRejected(rejected, triggeringType, transactions)
	}
	if triggeringType != typeurl.Count {
		// Only dependent inverses containing a rejected triggering name can
		// restore its whole predecessor transaction. Use the name index rather
		// than scanning unrelated owners, and visit each owner once.
		owners, _ := r.dependents.Get(triggeringType)
		var rebased set.Set[*rollbackLifecycle]
		for name := range rejected[triggeringType] {
			for lifecycle := range owners[name].Members() {
				if !rebased.Has(lifecycle) {
					lifecycle.dependents.rebaseRejected(rejected, triggeringType, transactions)
					rebased.Insert(lifecycle)
				}
			}
		}
	}
	for typeURL, entries := range rejected {
		owners, _ := r.dependents.Get(typeurl.Index(typeURL))
		for name, rejectedEntry := range entries {
			if triggeringType != typeurl.Count && typeurl.Index(typeURL) != triggeringType && !transactions.Has(rejectedEntry.expectedTransaction) {
				continue
			}
			for lifecycle := range owners[name].Members() {
				dependent := lifecycle.dependents[typeURL][name]
				if dependent.previous.transaction == rejectedEntry.expectedTransaction {
					dependent.previous = rejectedEntry.previous
					lifecycle.dependents[typeURL][name] = dependent
				}
			}
		}
	}
	for lifecycle := range r.callers.Members() {
		inverse := &lifecycle.inverse
		if inverse.hasSingleton() {
			singleton := &inverse.singleton
			entry, exists := rejected[singleton.typeURL][singleton.name]
			if exists && singleton.entry.transaction == entry.expectedTransaction &&
				(triggeringType == typeurl.Count || singleton.typeURL == triggeringType || transactions.Has(entry.expectedTransaction)) {
				singleton.entry = entry.previous
			}
			continue
		}
		// A caller inverse restores one whole API transaction. If it would
		// resurrect a rejected triggering value, bypass the other values from
		// that same predecessor too. An independent member-only inverse cannot
		// establish this relationship and must keep its preserved target.
		var restoringTransactions set.Set[callbacks.TransactionID]
		if triggeringType != typeurl.Count {
			for name, entry := range rejected[triggeringType] {
				if inverse.entries[triggeringType][name].transaction == entry.expectedTransaction {
					restoringTransactions.Insert(entry.expectedTransaction)
				}
			}
		}
		for typeURL, entries := range rejected {
			for name, entry := range entries {
				if triggeringType != typeurl.Count && typeurl.Index(typeURL) != triggeringType &&
					!transactions.Has(entry.expectedTransaction) && !restoringTransactions.Has(entry.expectedTransaction) {
					continue
				}
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

// reusedResources is a temporary list, not another desired-resource index.
// Only names, types and transaction identities are needed; one entry stays inline.
type reusedResources struct {
	first reusedResource
	more  []reusedResource
}

type reusedResource struct {
	name        string
	transaction callbacks.TransactionID
	typeURL     typeurl.Index
}

func (reused *reusedResources) insert(typeURL typeurl.Index, name string, transaction callbacks.TransactionID, capacity int) {
	entry := reusedResource{name: name, transaction: transaction, typeURL: typeURL}
	if reused.first.name == "" {
		reused.first = entry
	} else {
		if reused.more == nil {
			// Preparation bounds the number of no-op names. Allocate only when
			// a second live value is actually found, avoiding repeated growth
			// for genuinely mixed bulk updates without penalizing 0/1 reuse.
			reused.more = make([]reusedResource, 0, capacity)
		}
		reused.more = append(reused.more, entry)
	}
}

// collectUnchangedResources reuses preparation's no-op decisions without
// comparing protobufs again. Do not return an iterator here: repeatedly
// capturing the bulk mutation and inverse for each rollback owner is expensive.
func collectUnchangedResources[V any](reused *reusedResources, current map[string]resourceEntry, removed, upserted map[string]V, inverse *resources, typeURL typeurl.Index, capacity int) {
	for name := range removed {
		if _, replaced := upserted[name]; replaced {
			continue
		}
		if _, changed := inverse.get(typeURL, name); !changed && !current[name].transaction.IsZero() {
			reused.insert(typeURL, name, current[name].transaction, capacity)
		}
	}
	for name := range upserted {
		if _, changed := inverse.get(typeURL, name); !changed && !current[name].transaction.IsZero() {
			reused.insert(typeURL, name, current[name].transaction, capacity)
		}
	}
}

func (r *rollbackState) unchangedResources(state *nodeState, mutations *ResourceMutations, inverse *resources, capacity int) reusedResources {
	var reused reusedResources
	collectUnchangedResources(&reused, state.resources[typeurl.Listener], mutations.Removed.Listeners, mutations.Upserted.Listeners, inverse, typeurl.Listener, capacity)
	collectUnchangedResources(&reused, state.resources[typeurl.Route], mutations.Removed.Routes, mutations.Upserted.Routes, inverse, typeurl.Route, capacity)
	collectUnchangedResources(&reused, state.resources[typeurl.Cluster], mutations.Removed.Clusters, mutations.Upserted.Clusters, inverse, typeurl.Cluster, capacity)
	collectUnchangedResources(&reused, state.resources[typeurl.Endpoint], mutations.Removed.Endpoints, mutations.Upserted.Endpoints, inverse, typeurl.Endpoint, capacity)
	collectUnchangedResources(&reused, state.resources[typeurl.Secret], mutations.Removed.Secrets, mutations.Upserted.Secrets, inverse, typeurl.Secret, capacity)
	return reused
}

// pendingDependencies captures reused values before mutation. Publication may
// partition response owners, which are resolved separately after success.
func (r *rollbackState) pendingDependencies(state *nodeState, reused *reusedResources, waits *typeurl.Map[callbacks.ResourceScope]) *typeurl.Map[set.Set[callbacks.TransactionID]] {
	if reused.first.name == "" || state.pendingPublication == nil {
		return nil
	}
	var pending *typeurl.Map[set.Set[callbacks.TransactionID]]
	for responseType := range state.pendingPublication.rollbacks.Keys() {
		triggeringChanges, _ := state.pendingPublication.rollbacks.Get(responseType)
		var dependents rollbackResources
		if state.pendingPublication.dependents != nil {
			dependents, _ = state.pendingPublication.dependents.Get(responseType)
		}
		transactions := triggeringChanges.dependencyTransactions(reused, responseType, &dependents)
		if transactions.Empty() {
			continue
		}
		if pending == nil {
			pending = new(typeurl.Map[set.Set[callbacks.TransactionID]])
		}
		pending.Set(responseType, transactions)
		triggeringChanges.addDependencyScope(state, responseType, transactions, waits)
	}
	return pending
}

// pruneAbsentDependentResource drops relationships whose value cannot be
// restored anymore. An absent entry (not a transaction-tagged tombstone) has
// neither a current value nor a live rollback able to restore that transaction.
// This bounds dependency bookkeeping during add/remove churn while another
// resource's response remains unacknowledged. Call only after a successful
// mutation or terminal lifecycle operation, never during publication recovery.
func (r *rollbackState) pruneAbsentDependentResource(state *nodeState, typeURL typeurl.Index, name string) {
	current := state.resourceEntries(typeURL)[name]
	if current.resource != nil || !current.transaction.IsZero() {
		return
	}
	prune := func(rollback *rollbackResources) {
		if entry, exists := rollback[typeURL][name]; exists {
			state.typeStates[typeURL].rollbacks.removeOwner(rollbackOwnerKey{name: name, transaction: entry.expectedTransaction})
			delete(rollback[typeURL], name)
		}
	}
	owners, _ := r.dependents.Get(typeURL)
	for response := range owners[name].Members() {
		prune(response.dependents)
		r.removeDependentRollback(response, typeURL, name)
		if response.dependents.empty() {
			response.dependents = nil
		}
	}
	if state.pendingPublication != nil && state.pendingPublication.dependents != nil {
		for responseType, rollback := range state.pendingPublication.dependents.All() {
			prune(&rollback)
			if rollback.empty() {
				state.pendingPublication.dependents.Remove(responseType)
			}
		}
		if state.pendingPublication.dependents.Empty() {
			state.pendingPublication.dependents = nil
		}
	}
}

func (r *rollbackState) hasDependents(state *nodeState) bool {
	if state.pendingPublication != nil && state.pendingPublication.dependents != nil {
		return true
	}
	return !r.dependents.Empty()
}

func (r *rollbackState) pruneAbsentDependentChanges(state *nodeState, changes resourceChanges) {
	if !changes.empty() {
		r.pruneAbsentDependentResource(state, changes.first.typeURL, changes.first.name)
	}
	for _, change := range changes.more {
		r.pruneAbsentDependentResource(state, change.typeURL, change.name)
	}
}

// completeStrictResourceRevert closes the proposed response rollback over its
// remaining dependencies. Transaction IDs protect independent newer updates,
// but cannot preserve a Listener that still requires a Route being removed by
// a NACK. Such a Listener is restored too, or removed if its previous references
// cannot be restored. Conversely, losing a child's last reference removes that
// child, including later edits and resources outside the original transaction.
//
// Work is limited to names affected by the proposed rollback. Repeat only when
// an added dependency change affects another name; content-only child reverts
// do not cascade to parents. Caller must hold the cache mutex.
func (r *rollbackState) completeStrictResourceRevert(state *nodeState, changes *resourceChanges, rollback rollbackResources) {
	if state.strictRefs == nil {
		state.strictRefs = &strictReferenceCounts{}
	}
	refs := state.strictRefs
	var proposed strictConsistencyChanges
	proposed.add(changes.first)
	for _, change := range changes.more {
		proposed.add(change)
	}
	set := func(typeURL typeurl.Index, name string, next resourceEntry) bool {
		current := state.resources[typeURL][name]
		previous := changes.resourceAfter(typeURL, name, current.resource)
		if previous == next.resource {
			return false
		}
		// Update reference deltas using the already-proposed value, while the
		// prepared mutation itself continues to start from the desired entry.
		proposed.add(resourceChange{typeURL: typeURL, name: name, previous: resourceEntry{resource: previous}, next: next})
		changes.set(typeURL, name, current, next)
		return true
	}
	for {
		changed := false
		for name, candidate := range proposed.routes {
			count := refs.routes[name] + candidate.referenceDelta
			route := changes.resourceAfter(typeurl.Route, name, state.resources[typeurl.Route][name].resource)
			if count > 0 && route == nil {
				for listenerName, entry := range state.resources[typeurl.Listener] {
					listener := changes.resourceAfter(typeurl.Listener, listenerName, entry.resource)
					if !strictParentReferences(listener, typeurl.Route).Has(name) {
						continue
					}
					previous := rollback[typeurl.Listener][listenerName].previous
					if strictParentReferences(previous.resource, typeurl.Route).Has(name) {
						// A previous Listener requiring the rejected Route is no
						// fallback. Remove it rather than retain poisoned state.
						previous = resourceEntry{}
					}
					changed = set(typeurl.Listener, listenerName, previous) || changed
				}
			}
		}
		if !changed {
			break
		}
	}
	// Settle parent references first: restoring a Listener may make an otherwise
	// orphaned Route necessary. Pruning children earlier would make recovery
	// depend on map iteration order and could discard a usable old configuration.
	for name, candidate := range proposed.routes {
		if refs.routes[name]+candidate.referenceDelta == 0 {
			set(typeurl.Route, name, resourceEntry{})
		}
	}
	for name, candidate := range proposed.endpoints {
		if refs.endpoints[name]+candidate.referenceDelta == 0 {
			set(typeurl.Endpoint, name, resourceEntry{})
		}
	}
}

// liveDependencyTransactions keeps only prerequisite identities referenced by
// coalesced dependent entries, not every past mutation of a resource.
//
// Most updates, notably NPDS, use single-resource APIs and create no dependent
// relationships. NPDS/NPHDS cannot participate in bulk transactions at all.
// Bulk updates mainly reconcile CEC/CCEC-owned resource sets, normally separate
// from policy-enforcement Listeners; service-derived CLAs are synced separately.
// Protocol references to those CLAs alone create no transaction dependencies
// here: a bulk update must change some supplied resources while explicitly
// reusing another with pending response ownership, directly or through an
// earlier dependency. Its value may be ACKed while a prerequisite is not.
//
// Partial CEC/CCEC updates normally reuse fully acknowledged state and add no
// dependencies. High-churn partial CEC/CCEC updates are expected to be rare;
// these loops become costly when many pending relationships accumulate, e.g.
// repeated partial updates while Envoy is slow or disconnected. Independent
// single-resource CLA updates do not contribute, even if never subscribed to.
func (r *rollbackState) liveDependencyTransactions(state *nodeState) set.Set[callbacks.TransactionID] {
	var transactions set.Set[callbacks.TransactionID]
	if state.pendingPublication != nil && state.pendingPublication.dependents != nil {
		for _, dependents := range state.pendingPublication.dependents.All() {
			for _, entries := range dependents {
				for _, entry := range entries {
					transactions.Merge(entry.transactions)
				}
			}
		}
	}
	for typeURL, owners := range r.dependents.All() {
		for name, lifecycles := range owners {
			for lifecycle := range lifecycles.Members() {
				transactions.Merge(lifecycle.dependents[typeURL][name].transactions)
			}
		}
	}
	return transactions
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
		rollback[typeURL] = state.rollbacks.mergeHistoryMap(state, typeURL, rollback[typeURL], newer[typeURL], nil)
	}
	return rollback
}

// liveTransactionIDs includes observable current members and prerequisites
// still needed by dependents, so pruning cannot sever a live relationship.
func (rollback rollbackResources) liveTransactionIDs(state *nodeState, snapshot cache.ResourceSnapshot) set.Set[callbacks.TransactionID] {
	var live set.Set[callbacks.TransactionID]
	for index, entries := range rollback {
		for name, entry := range entries {
			if state.resources[index][name].transaction == entry.expectedTransaction && state.rollbacks.resourceStateIsObservable(state, snapshot, typeurl.Index(index), name) {
				live.Insert(entry.expectedTransaction)
			}
		}
	}
	live.Merge(state.rollbacks.liveDependencyTransactions(state))
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

func (rollback rollbackResources) rebaseRejected(rejected rollbackResources, triggeringType typeurl.Index, transactions set.Set[callbacks.TransactionID]) {
	// Coalesced response inverses can contain several transactions. Only members
	// of an inverse which would restore a rejected triggering value share that
	// predecessor's rejection; an independent member-only inverse is preserved.
	if triggeringType != typeurl.Count {
		for name, rejectedChange := range rejected[triggeringType] {
			change, exists := rollback[triggeringType][name]
			if !exists || change.previous.transaction != rejectedChange.expectedTransaction {
				continue
			}
			for typeURL, entries := range rollback {
				if typeurl.Index(typeURL) == triggeringType {
					continue // Directly rejected targets are handled below.
				}
				for memberName, member := range entries {
					if member.expectedTransaction != change.expectedTransaction ||
						member.previous.transaction != rejectedChange.expectedTransaction {
						continue
					}
					rejectedEntry, exists := rejected[typeURL][memberName]
					if exists && member.previous.transaction == rejectedEntry.expectedTransaction {
						member.previous = rejectedEntry.previous
						rollback[typeURL][memberName] = member
					}
				}
			}
		}
	}
	for typeURL, entries := range rejected {
		for name, rejectedEntry := range entries {
			if triggeringType != typeurl.Count && typeurl.Index(typeURL) != triggeringType && !transactions.Has(rejectedEntry.expectedTransaction) {
				continue
			}
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

func (rollback rollbackResources) containsTransaction(typeURL typeurl.Index, name string, transaction callbacks.TransactionID) bool {
	entry, exists := rollback[typeURL][name]
	return exists && entry.expectedTransaction == transaction
}

func (rollback rollbackResources) mergeDependentTransaction(state *nodeState, triggeringChanges rollbackResources, inverse resources, transaction callbacks.TransactionID, prerequisites set.Set[callbacks.TransactionID]) rollbackResources {
	for typeURL := range typeurl.Indices() {
		if inverse.len(typeURL) == 0 {
			continue
		}
		typeState := &state.typeStates[typeURL]
		entries := rollback[typeURL]
		if entries == nil {
			entries = make(map[string]rollbackEntry, inverse.len(typeURL))
		}
		for name, previous := range inverse.resources(typeURL) {
			entry, exists := entries[name]
			if !exists {
				entry.previous = previous
			}
			desired := state.resources[typeURL][name]
			if exists {
				typeState.rollbacks.removeOwner(rollbackOwnerKey{name: name, transaction: entry.expectedTransaction})
			}
			// A new inverse is already known to differ semantically from the
			// committed value; only coalescing needs another comparison.
			if exists && entry.previousEquals(desired.resource) &&
				!triggeringChanges.containsTransaction(typeURL, name, entry.previous.transaction) {
				delete(entries, name)
				continue
			}
			// Returning to A's value still depends on A. Keep its new transaction
			// as an alias, so C using that value inherits the pending dependency.
			// Other net no-ops disappear, just like ordinary unsent rollback.
			entry.expectedTransaction = transaction
			entry.transactions.Merge(prerequisites)
			if desired.resource == nil {
				// Successful publication may already have pruned a net-zero
				// tombstone. Its pending prerequisite still needs this transaction
				// to identify the dependent value; the wire view stays absent.
				if desired.transaction.IsZero() {
					if state.resources[typeURL] == nil {
						state.resources[typeURL] = make(map[string]resourceEntry)
					}
					state.resources[typeURL][name] = resourceEntry{revision: transaction.InitialRevision(), transaction: transaction}
				}
				typeState.rollbacks.addOwner(rollbackOwnerKey{name: name, transaction: transaction})
			}
			entries[name] = entry
		}
		if len(entries) == 0 {
			entries = nil
		}
		rollback[typeURL] = entries
	}
	return rollback
}

// withDependents projects the oldest rollback target and newest transaction for
// every affected name. Only NACK processing needs this temporary copy; the
// independently owned maps and their tombstone references remain unchanged.
func (rollback rollbackResources) withDependents(dependents *rollbackResources) rollbackResources {
	if dependents == nil {
		return rollback
	}
	rollback = rollback.clone()
	for typeURL := range typeurl.Indices() {
		for name, dependent := range dependents[typeURL] {
			if previous, exists := rollback[typeURL][name]; exists {
				dependent.previous = previous.previous
			}
			if rollback[typeURL] == nil {
				rollback[typeURL] = make(map[string]rollbackEntry)
			}
			rollback[typeURL][name] = dependent
		}
	}
	return rollback
}

// normalizeDependencies replaces obsolete unsent prerequisite identities with
// the current triggering resource changes which coalesced them. Their
// intermediate values were never delivered, so keeping every historical
// transaction serves no response.
// Claimed lifecycles are immutable here: their identities remain distinct until
// ACK or NACK.
func (rollback rollbackResources) normalizeDependencies(state *nodeState, responseType typeurl.Index, dependents *rollbackResources) {
	if dependents == nil {
		return
	}
	triggeringChanges := rollback[responseType]
	var live set.Set[callbacks.TransactionID]
	for _, change := range triggeringChanges {
		live.Insert(change.expectedTransaction)
	}
	for index, entries := range *dependents {
		for name, entry := range entries {
			canonical := true
			for transaction := range entry.transactions.Members() {
				if !live.Has(transaction) {
					canonical = false
					break
				}
			}
			if canonical {
				continue
			}
			var retained set.Set[callbacks.TransactionID]
			for transaction := range entry.transactions.Members() {
				if live.Has(transaction) {
					retained.Insert(transaction)
					continue
				}
				for _, change := range triggeringChanges {
					if change.expectedTransaction == transaction || change.transactions.Has(transaction) {
						retained.Insert(change.expectedTransaction)
					}
				}
			}
			if retained.Empty() {
				state.typeStates[index].rollbacks.removeOwner(rollbackOwnerKey{name: name, transaction: entry.expectedTransaction})
				delete(entries, name)
			} else {
				entry.transactions = retained
				entries[name] = entry
			}
		}
	}
}

// dependencyTransactions uses prepared no-op decisions rather than another
// protobuf comparison. Explicit dependent entries propagate the original
// prerequisites through A -> B -> C; unrelated transaction members are not
// prerequisites.
func (rollback rollbackResources) dependencyTransactions(reused *reusedResources, responseType typeurl.Index, dependents *rollbackResources) set.Set[callbacks.TransactionID] {
	var transactions set.Set[callbacks.TransactionID]
	visit := func(typeURL typeurl.Index, name string, transaction callbacks.TransactionID) {
		if responseType == typeURL && rollback.containsTransaction(typeURL, name, transaction) {
			transactions.Insert(transaction)
		}
		if dependents != nil && dependents.containsTransaction(typeURL, name, transaction) {
			transactions.Merge(dependents[typeURL][name].transactions)
		}
	}
	entry := reused.first
	visit(entry.typeURL, entry.name, entry.transaction)
	for _, entry := range reused.more {
		visit(entry.typeURL, entry.name, entry.transaction)
	}
	return transactions
}

// addDependencyScope preserves a live wait's prerequisites independently of
// the coalesced resource inverse. Replacing that inverse must not lose older
// waiters, and named responses must resolve only the prerequisites they cover.
func (rollback rollbackResources) addDependencyScope(state *nodeState, responseType typeurl.Index, transactions set.Set[callbacks.TransactionID], waits *typeurl.Map[callbacks.ResourceScope]) {
	if waits == nil {
		return
	}
	scope, _ := waits.Get(responseType)
	for name, entry := range rollback[responseType] {
		if transactions.Has(entry.expectedTransaction) {
			// Prerequisite identity follows the API transaction, but a wait must
			// require its current revision: a revert can restore that transaction
			// with a newer named value than an older ACK actually covered.
			current := state.resourceWaitEntry(responseType, name)
			scope.Insert(name, current.revision)
			waits.Set(responseType, scope)
		}
	}
}

// markPrerequisites preserves a prerequisite's identity when a newer unsent
// value replaces it. Its dependent transaction still belongs to that chain.
func (rollback rollbackResources) markPrerequisites(transactions set.Set[callbacks.TransactionID]) {
	for _, entries := range rollback {
		for name, entry := range entries {
			if transactions.Has(entry.expectedTransaction) {
				entry.transactions.Insert(entry.expectedTransaction)
				entries[name] = entry
			}
		}
	}
}

// partitionDependents moves relationships with selected prerequisite
// transactions into their response. A dependent using prerequisites on both
// sides needs independent ownership, including a second tombstone reference.
func (rollback *rollbackResources) partitionDependents(state *nodeState, selected set.Set[callbacks.TransactionID]) rollbackResources {
	var sent rollbackResources
	for typeURL := range typeurl.Indices() {
		for name, entry := range rollback[typeURL] {
			var served, remaining set.Set[callbacks.TransactionID]
			for transaction := range entry.transactions.Members() {
				if selected.Has(transaction) {
					served.Insert(transaction)
				} else {
					remaining.Insert(transaction)
				}
			}
			if served.Empty() {
				continue
			}
			if sent[typeURL] == nil {
				sent[typeURL] = make(map[string]rollbackEntry)
			}
			servedEntry := entry
			servedEntry.transactions = served
			sent[typeURL][name] = servedEntry
			if remaining.Empty() {
				delete(rollback[typeURL], name)
			} else {
				entry.transactions = remaining
				rollback[typeURL][name] = entry
				if state.resources[typeURL][name].resource == nil {
					state.typeStates[typeURL].rollbacks.addOwner(rollbackOwnerKey{name: name, transaction: entry.expectedTransaction})
				}
			}
		}
		if len(rollback[typeURL]) == 0 {
			rollback[typeURL] = nil
		}
	}
	return sent
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

func (lifecycle *rollbackLifecycle) retainDependentTransactionLocked(state *nodeState, inverse resources, transaction callbacks.TransactionID, prerequisites set.Set[callbacks.TransactionID]) {
	lifecycle.resources.markPrerequisites(prerequisites)
	if lifecycle.dependents == nil {
		lifecycle.dependents = new(rollbackResources)
	}
	*lifecycle.dependents = lifecycle.dependents.mergeDependentTransaction(state, *lifecycle.resources, inverse, transaction, prerequisites)
	if lifecycle.dependents.empty() {
		lifecycle.dependents = nil
	}
	// Merging changes only names in this inverse. Preserve existing singleton
	// owner sets and maps rather than rebuilding the whole lifecycle's index.
	for typeURL := range typeurl.Indices() {
		for name := range inverse.resources(typeURL) {
			var present bool
			if lifecycle.dependents != nil {
				_, present = lifecycle.dependents[typeURL][name]
			}
			if present {
				state.rollbacks.insertDependentRollback(lifecycle, typeURL, name)
			} else {
				state.rollbacks.removeDependentRollback(lifecycle, typeURL, name)
			}
		}
	}
	snapshot, _ := lifecycle.cache.SnapshotCache.GetSnapshot(lifecycle.nodeID)
	lifecycle.cache.completionCbs.SetGenerationTransactions(lifecycle.nodeID, lifecycle.typeURL, lifecycle.generation,
		lifecycle.transactionIDs(state, snapshot))
}

// transactionIDs includes dependent callers even when they only wait
// for another TypeURL. Failing the prerequisite must fail those waits too,
// not just revert their desired resources while leaving the caller stranded.
// Caller must hold cacheImpl.mutex.
func (lifecycle *rollbackLifecycle) transactionIDs(state *nodeState, snapshot cache.ResourceSnapshot) set.Set[callbacks.TransactionID] {
	transactions := lifecycle.resources.transactionIDs(state, snapshot)
	if lifecycle.dependents != nil {
		for _, entries := range *lifecycle.dependents {
			for _, entry := range entries {
				transactions.Insert(entry.expectedTransaction)
			}
		}
	}
	return transactions
}
