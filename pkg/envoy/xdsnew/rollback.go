// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"maps"
	"slices"

	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// rollbackState owns the node's live caller/response rollbacks. Methods borrow
// node or transaction context for desired resources and publication; they never
// take the cache lock or invoke user callbacks. All access requires cacheImpl.mutex.
type rollbackState struct {
	// Response outcome releases these inverses independently of caller lifetime.
	responses set.Set[*responseRollback]
	// Caller resolution is terminal; these are live inverses, not history.
	callers set.Set[*callerRollback]
}

// callerRollback owns recovery for one API transaction, independently of Envoy's
// response. Revert and Finalize are terminal, even if reverting fails. Mutable
// fields require cache.mutex. Membership in rollbackState.callers denotes an
// outstanding handle, even when later callers have superseded its entire payload.
type callerRollback struct {
	cache *cacheImpl
	ctx   context.Context
	// Known nodes persist for the cache's lifetime, so resolution can reuse this
	// reference after resources are removed or streams disconnect.
	state *nodeState
	// transaction is fixed when the API mutation commits and guards upsert reverts.
	transaction callbacks.TransactionID
	inverse     resources
	// Only caller recovery retains deleted values. A newer API deletion removes
	// its name from these claims, including when that deletion is a no-op. No
	// tombstone is needed in desired state.
	removed *resources
}

// responseRollback owns recovery for one resource type in an Envoy response.
// It may coalesce several API transactions before delivery. Failed recovery
// retains its state for a later NACK, independently of caller resolution.
// Mutable fields require cache.mutex; nil resources denotes resolution.
type responseRollback struct {
	cache      *cacheImpl
	state      *nodeState
	typeURL    typeurl.Index
	generation callbacks.Generation
	// A non-nil map owns recovery even while temporarily empty during coalescing.
	resources rollbackResources
}

type rollbackEntry struct {
	previous resourceEntry
	// expectedTransaction identifies the API change this inverse can undo.
	expectedTransaction callbacks.TransactionID
}

// rollbackResources contains response-owned recovery for one resource type.
// Response recovery undoes only upserts. Only caller recovery can undo removals.
type rollbackResources map[string]rollbackEntry

// adoptNonRevertibleLocked changes ownership without changing the value,
// revision, transaction, or published snapshot. Sent inverses keep their
// response identity but their per-entry guards now prevent undoing this value.
func (r *rollbackState) adoptNonRevertibleLocked(c *cacheImpl, state *nodeState, typeURL typeurl.Index, name string) {
	entry := state.resources[typeURL][name]
	if entry.resource == nil || entry.nonRevertible {
		return
	}
	entry.nonRevertible = true
	state.resources[typeURL][name] = entry
	if pending := state.pendingPublication; pending != nil {
		rollback, _ := pending.rollbacks.Get(typeURL)
		delete(rollback, name)
		if len(rollback) == 0 && pending.rollbacks.Has(typeURL) {
			pending.rollbacks.Set(typeURL, nil)
		}
	}
	if unsent := state.typeStates[typeURL].unsentRollback; unsent != nil {
		delete(unsent.resources, name)
		if len(unsent.resources) == 0 && c.completionCbs.DiscardUnsentTypeGeneration(state.nodeID, typeURL, unsent.generation) {
			unsent.finalizeLocked()
		}
	}
}

func (tx *resourceTransaction) adoptNonRevertibleUpsertsLocked(upserted xds.Resources) {
	r, c, state := &tx.state.rollbacks, tx.cache, tx.state
	for name := range upserted.Listeners {
		r.adoptNonRevertibleLocked(c, state, typeurl.Listener, name)
	}
	for name := range upserted.Routes {
		r.adoptNonRevertibleLocked(c, state, typeurl.Route, name)
	}
	for name := range upserted.Clusters {
		r.adoptNonRevertibleLocked(c, state, typeurl.Cluster, name)
	}
	for name := range upserted.Endpoints {
		r.adoptNonRevertibleLocked(c, state, typeurl.Endpoint, name)
	}
	for name := range upserted.Secrets {
		r.adoptNonRevertibleLocked(c, state, typeurl.Secret, name)
	}
}

// preparePublicationLocked coalesces rollback ownership for committed entries.
// Save recovery maps only when immediate publication can fail. The node is
// borrowed from tx; the ledger does not allocate another owner or retain a
// back-pointer to desired state. Caller must hold cacheImpl.mutex.
func (r *rollbackState) preparePublicationLocked(tx *resourceTransaction, changedTypeURLs, removedTypes typeurl.Set, options resourceUpdateOptions) (oldPending *pendingPublication, oldPendingValue pendingPublication, willFinalize bool) {
	state := tx.state
	dirtyTypeURLs := snapshotTypesChangedBy(changedTypeURLs)
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
		// Only immediate publication can fail after committing desired entries.
		// Clone recovery maps here, avoiding copies on every deferred mutation.
		for typeURL, rollback := range oldPending.rollbacks.All() {
			oldPendingValue.rollbacks.Set(typeURL, maps.Clone(rollback))
		}
	}
	if options.trackRollback {
		for typeURL := range changedTypeURLs.Members() {
			current, _ := rollbacks.Get(typeURL)
			if removedTypes.Has(typeURL) {
				// A removal ends this name's unpublished recovery chain, even
				// when the snapshot will project a synthesized empty CLA.
				current.pruneRemovedResources(state, typeURL)
			}
			transaction := tx.generation.TransactionID()
			for name, previous := range options.inverse.resources(typeURL) {
				entry, exists := current[name]
				if !exists {
					entry.previous = previous
				} else if entry.previousEquals(state.resources[typeURL][name].resource) {
					// No response saw this chain. Returning to its original contents
					// eliminates response recovery while retaining caller ownership.
					delete(current, name)
					continue
				}
				if current == nil {
					current = make(rollbackResources, options.inverse.len(typeURL))
				}
				entry.expectedTransaction = transaction
				current[name] = entry
			}
			if len(current) == 0 {
				current = nil
			}
			rollbacks.Set(typeURL, current)
		}
	} else if options.isAPIUpdate {
		for typeURL := range changedTypeURLs.Members() {
			rollback, _ := rollbacks.Get(typeURL)
			if removedTypes.Has(typeURL) {
				rollback.pruneRemovedResources(state, typeURL)
			}
			// Plain API upserts are authoritative even before publication. Drop
			// earlier recovery for these names instead of extending its guard to
			// a non-revertible transaction.
			for name := range options.inverse.resources(typeURL) {
				delete(rollback, name)
			}
			if len(rollback) == 0 {
				rollback = nil
			}
			rollbacks.Set(typeURL, rollback)
		}
	} else {
		// Compensation can shorten an unpublished chain or restore an earlier
		// API value. Keep its existing baseline guarded by the restored origin.
		for typeURL := range changedTypeURLs.Members() {
			rollback, _ := rollbacks.Get(typeURL)
			rollback.reconcileDesiredState(state, typeURL)
			if len(rollback) == 0 {
				rollback = nil
			}
			rollbacks.Set(typeURL, rollback)
		}
	}
	// Include indirectly affected types so publication also reconciles their
	// earlier unsent rollback. Preserve any new rollback for the same type.
	for typeURL := range typeurl.Count {
		if !rollbacks.Has(typeURL) && dirtyTypeURLs.Has(typeURL) {
			rollbacks.Set(typeURL, nil)
		}
	}
	pending := oldPending
	if pending == nil {
		pending = &pendingPublication{}
	}
	*pending = pendingPublication{
		generation: tx.generation, changedTypeURLs: mergedTypeURLs,
		watchTypeURLs: watchTypeURLs, rollbacks: rollbacks,
	}
	state.pendingPublication = pending
	return oldPending, oldPendingValue, willFinalize
}

// restorePublicationLocked restores pending bookkeeping after failed admission.
// Desired entries have already been restored from the prepared changes.
func (r *rollbackState) restorePublicationLocked(state *nodeState, oldPending *pendingPublication, oldPendingValue pendingPublication) {
	if oldPending == nil {
		state.pendingPublication = nil
	} else {
		*oldPending = oldPendingValue
		state.pendingPublication = oldPending
	}
}

// publishedLocked transfers pending inverses to unsent response ownership only
// after snapshot installation succeeds. Caller must hold cacheImpl.mutex.
func (r *rollbackState) publishedLocked(c *cacheImpl, state *nodeState, pending *pendingPublication) {
	// Until go-control-plane actually produces a response, repeated published
	// generations are coalesced into one rollback per type. An older mutation
	// without a WaitGroup may precede a tracked mutation in the same eventual
	// response, and a NACK must restore the state before that whole batch.
	for typeURL, rollback := range pending.rollbacks.All() {
		if len(rollback) == 0 && state.typeStates[typeURL].unsentRollback == nil {
			continue
		}
		r.retainUnsentLocked(c, state, typeURL, pending.generation, rollback)
	}
}

// retainUnsentLocked keeps one coalesced rollback for a resource type
// until go-control-plane produces a response carrying the current version.
// Register it before delivery so the response can acquire its inverse even
// when the caller supplied no WaitGroup. A reconnecting client's echoed version
// alone cannot prove which names it received; retain the inverse until an
// actual response establishes acceptance or rejection.
// Caller holds the cache lock and supplies nonempty rollback state or an existing
// unsent chain.
func (r *rollbackState) retainUnsentLocked(c *cacheImpl, state *nodeState, typeURL typeurl.Index, generation callbacks.Generation, resources rollbackResources) {
	nodeID := state.nodeID
	if existing := state.typeStates[typeURL].unsentRollback; existing != nil {
		c.completionCbs.CoalesceUnsentTypeGeneration(nodeID, typeURL, existing.generation, generation, nil)
		if len(resources) == 0 {
			// A deferred A-B-A can leave no new inverse while this unsent
			// publication still owns the earlier rollback baseline.
			existing.resources.reconcileDesiredState(state, typeURL)
		}
		existing.resources = existing.resources.mergeHistory(state, typeURL, resources)
		existing.generation = generation
		if len(existing.resources) == 0 && c.completionCbs.DiscardUnsentTypeGeneration(nodeID, typeURL, generation) {
			// The cache lock prevents a response from claiming this unsent
			// generation between coalescing it and discarding it.
			// No rollback-eligible updates remain for this resource type. Caller
			// rollback retains its independently owned inverse.
			existing.finalizeLocked()
		}
		return
	}

	// Response rollback must outlive the context of the mutation which created
	// it. A later NACK remains actionable after that caller has timed out.
	rollback := r.newResponseLocked(c, state, typeURL, generation, resources)
	c.completionCbs.AddTypeGenerationWithRollback(generation, typeURL, nodeID, rollback, nil)
	state.typeStates[typeURL].unsentRollback = rollback
}

// claimResponseLocked freezes only resource names represented by this response.
// Unrequested names remain unsent and can coalesce with further mutations,
// including when they were changed in the same API transaction.
func (r *rollbackState) claimResponseLocked(c *cacheImpl, state *nodeState, typeURL typeurl.Index, response cache.Response) {
	nodeID := state.nodeID
	rollback := state.typeStates[typeURL].unsentRollback
	if rollback == nil || rollback.resources == nil {
		return
	}
	resources := rollback.resources
	// Full-state wildcard groups need no name map. Named groups (and types
	// without implicit deletion) capture their actual requirements once here.
	if callbacks.ResponseCoversType(response, rollback.generation) &&
		(typeURL == typeurl.Listener || typeURL == typeurl.Cluster || typeURL == typeurl.NetworkPolicy || typeURL == typeurl.NetworkPolicyHosts) {
		c.completionCbs.CoalesceUnsentTypeGeneration(nodeID, typeURL, rollback.generation, rollback.generation, &callbacks.ResourceScope{})
		state.typeStates[typeURL].unsentRollback = nil
		return
	}
	var sent rollbackResources
	var sentScope *callbacks.ResourceScope
	var sentGeneration, remainingGeneration callbacks.Generation
	for name, entry := range resources {
		if callbacks.ResponseCoversResource(response, name, entry.expectedTransaction) {
			if sent == nil {
				sent = make(rollbackResources)
				sentScope = &callbacks.ResourceScope{}
			}
			sent[name] = entry
			// A response inverse is actionable from its originating API
			// transaction onward; caller waits require the current revision.
			sentScope.Insert(name, entry.expectedTransaction.InitialRevision())
			delete(resources, name)
			sentGeneration = sentGeneration.MaxTransaction(entry.expectedTransaction)
		} else {
			remainingGeneration = remainingGeneration.MaxTransaction(entry.expectedTransaction)
		}
	}
	if len(sent) == 0 {
		// A named response can contain only unchanged resources. Leave these
		// updates unclaimed so they can coalesce until their names are delivered.
		return
	}
	if len(resources) == 0 {
		rollback.resources = sent
		c.completionCbs.CoalesceUnsentTypeGeneration(nodeID, typeURL, rollback.generation, rollback.generation, sentScope)
		state.typeStates[typeURL].unsentRollback = nil
		return
	}
	oldGeneration := rollback.generation
	rollback.generation = remainingGeneration
	sentRollback := r.newResponseLocked(c, state, typeURL, sentGeneration, sent)
	c.completionCbs.PartitionUnsentTypeGeneration(nodeID, typeURL, oldGeneration,
		remainingGeneration, rollback, nil, sentGeneration, sentRollback, sentScope)
}

// newResponseLocked owns one rollback view until it is either finalized or
// reverted. Duplicate resolution calls are programming errors, but are
// deliberately harmless because the rollback crosses several asynchronous
// ownership boundaries.
// Caller must hold c.mutex.
func (r *rollbackState) newResponseLocked(c *cacheImpl, state *nodeState, typeURL typeurl.Index, generation callbacks.Generation, resources rollbackResources) *responseRollback {
	rollback := &responseRollback{
		cache:      c,
		state:      state,
		typeURL:    typeURL,
		generation: generation,
		resources:  resources,
	}
	r.responses.Insert(rollback)
	return rollback
}

// newCallerLocked records the originating API mutation after admission. Deleted
// values come from the prepared changes, captured under the same cache lock as
// the deletion, so a concurrent NACK cannot slip between capture and commit.
// Caller must hold c.mutex.
func (r *rollbackState) newCallerLocked(tx *resourceTransaction, inverse resources, changes *resourceChanges) *callerRollback {
	rollback := &callerRollback{
		cache:       tx.cache,
		ctx:         tx.ctx,
		state:       tx.state,
		transaction: tx.generation.TransactionID(),
		inverse:     inverse,
	}
	captureRemoval := func(change *resourceChange) {
		if change.next.resource != nil {
			return
		}
		if rollback.removed == nil {
			removed := singleResource(change.typeURL, change.name, change.previous)
			rollback.removed = &removed
			return
		}
		removed := rollback.removed
		if removed.hasSingleton() {
			singleton := removed.singleton
			removed.entries[singleton.typeURL] = map[string]resourceEntry{singleton.name: singleton.entry}
			removed.singleton = singletonResource{}
		}
		if removed.entries[change.typeURL] == nil {
			removed.entries[change.typeURL] = make(map[string]resourceEntry)
		}
		removed.entries[change.typeURL][change.name] = change.previous
	}
	captureRemoval(&changes.first)
	for i := range changes.more {
		captureRemoval(&changes.more[i])
	}
	r.callers.Insert(rollback)
	return rollback
}

// supersedeCallerRollbackLocked protects a later caller's admitted desired state
// from earlier caller recovery. Reusing a live value relinquishes its originating
// caller's inverse; requesting absence relinquishes earlier restoration claims.
// Response recovery and ACK requirements remain unchanged. Only successful API
// admission calls this, before registering its own caller handle, never corrective
// reverts. Outstanding callers are usually few; scanning avoids another index.
// Cache lock required.
func (r *rollbackState) supersedeCallerRollbackLocked(typeURL typeurl.Index, name string, current resourceEntry) {
	for rollback := range r.callers.Members() {
		if current.resource != nil {
			if rollback.transaction == current.transaction {
				rollback.inverse.remove(typeURL, name)
				return
			}
		} else if rollback.removed != nil {
			rollback.removed.remove(typeURL, name)
		}
	}
}

func supersedeCallerRollbacks[V interface {
	cache_types.Resource
	comparable
}](r *rollbackState, state *nodeState, typeURL typeurl.Index, removed, upserted map[string]V, inverse *resources) {
	for name := range removed {
		if _, replaced := upserted[name]; !replaced {
			r.supersedeCallerRollbackLocked(typeURL, name, resourceEntry{})
		}
	}
	var zero V
	for name, resource := range upserted {
		if resource == zero {
			r.supersedeCallerRollbackLocked(typeURL, name, resourceEntry{})
		} else if _, changed := inverse.get(typeURL, name); !changed {
			// Preparation already proved equality. Changed values have fresh
			// transactions and already fence earlier caller recovery.
			r.supersedeCallerRollbackLocked(typeURL, name, state.resources[typeURL][name])
		}
	}
}

func (r *rollbackState) supersedeCallerRollbacksLocked(state *nodeState, mutations ResourceMutations, inverse *resources) {
	if r.callers.Empty() {
		return
	}
	removed, upserted := mutations.Removed, mutations.Upserted
	supersedeCallerRollbacks(r, state, typeurl.Listener, removed.Listeners, upserted.Listeners, inverse)
	supersedeCallerRollbacks(r, state, typeurl.Route, removed.Routes, upserted.Routes, inverse)
	supersedeCallerRollbacks(r, state, typeurl.Cluster, removed.Clusters, upserted.Clusters, inverse)
	supersedeCallerRollbacks(r, state, typeurl.Endpoint, removed.Endpoints, upserted.Endpoints, inverse)
	supersedeCallerRollbacks(r, state, typeurl.Secret, removed.Secrets, upserted.Secrets, inverse)
}

// finalizeLocked releases caller recovery even after a failed revert.
// Caller must hold cacheImpl.mutex.
func (rb *callerRollback) finalizeLocked() {
	if !rb.state.rollbacks.callers.Has(rb) {
		rb.warnDuplicateLocked("finalize")
		return
	}
	rb.inverse = resources{}
	rb.removed = nil
	rb.state.rollbacks.callers.Remove(rb)
}

// Finalize releases the caller-owned rollback state after the enclosing
// transaction succeeds.
func (rb *callerRollback) Finalize() {
	c := rb.cache
	c.mutex.Lock()
	rb.finalizeLocked()
	c.mutex.Unlock()
}

// Revert restores desired resources after a caller failure.
// Upserts are transaction-fenced; caller-owned removals require absence and no
// superseding API deletion. Previous values and transactions are restored with
// fresh revisions, fencing ACK waits for restored state against older responses.
// Revert is terminal regardless of its returned error.
func (rb *callerRollback) Revert() error {
	c := rb.cache
	// Compensation must remain possible after the original mutation's caller
	// has timed out. Preserve context values without inheriting cancellation.
	tx := c.beginResourceTransaction(context.WithoutCancel(rb.ctx), rb.state)
	defer tx.complete()
	if !rb.state.rollbacks.callers.Has(rb) {
		rb.warnDuplicateLocked("revert")
		return nil
	}
	err := tx.applyRevertLocked(rb.prepareRevertLocked())
	rb.finalizeLocked()
	return err
}

// finalizeLocked releases response recovery after acceptance or a successful
// revert. Caller must hold cacheImpl.mutex.
func (rb *responseRollback) finalizeLocked() {
	if rb.resources == nil {
		rb.warnDuplicateLocked("finalize")
		return
	}
	rb.resources = nil
	state := rb.state
	if state.typeStates[rb.typeURL].unsentRollback == rb {
		state.typeStates[rb.typeURL].unsentRollback = nil
	}
	state.rollbacks.responses.Remove(rb)
}

// Finalize releases response-owned recovery independently of caller ownership.
func (rb *responseRollback) Finalize() {
	c := rb.cache
	c.mutex.Lock()
	rb.finalizeLocked()
	c.mutex.Unlock()
}

// Revert restores the rejected resource type with fresh revisions. Failed
// recovery retains its payload so a subsequent NACK can retry it.
func (rb *responseRollback) Revert() error {
	tx := rb.cache.beginResourceTransaction(context.Background(), rb.state)
	defer tx.complete()
	return tx.revertLocked([]Rollback{rb})
}

// prepareRevertLocked composes selected response inverses without mutating desired
// resources. Rejected predecessors are rebased before the atomic correction.
// Caller must hold cacheImpl.mutex.
func (r *rollbackState) prepareRevertLocked(tx *resourceTransaction, rollbacks []Rollback) (resourceChanges, error) {
	c, state := tx.cache, tx.state
	for _, rollback := range rollbacks {
		rollback, ok := rollback.(*responseRollback)
		if !ok || rollback == nil || rollback.cache != c || rollback.state != state {
			return resourceChanges{}, fmt.Errorf("rollback does not belong to cache node %s", state.nodeID)
		}
	}

	// Compose predecessor chains oldest first, before preparing any changes.
	// This also rebases later caller/response inverses which are not selected:
	// their eventual rollback must not resurrect a rejected predecessor. Rejection
	// is definitive even if publishing this correction subsequently fails.
	for _, rollback := range slices.Backward(rollbacks) {
		rollback := rollback.(*responseRollback)
		if rollback.resources != nil {
			r.rebaseRejected(state, rollback.typeURL, rollback.resources)
		}
	}

	var changes resourceChanges
	if len(rollbacks) == 1 {
		rollback := rollbacks[0].(*responseRollback)
		if rollback.resources == nil {
			rollback.warnDuplicateLocked("revert")
			return resourceChanges{}, nil
		}
		changes = rollback.resources.resourceRevert(state, rollback.typeURL)
	} else {
		var combined typeurl.Slots[rollbackResources]
		for _, rollback := range rollbacks {
			rollback := rollback.(*responseRollback)
			typeURL := rollback.typeURL
			for name, entry := range rollback.resources {
				current := state.resources[typeURL][name]
				if current.nonRevertible || current.transaction != entry.expectedTransaction {
					continue
				}
				if combined[typeURL] == nil {
					combined[typeURL] = make(map[string]rollbackEntry)
				}
				combined[typeURL][name] = entry
			}
		}
		for typeURL := range typeurl.Count {
			current := state.resources[typeURL]
			for name, entry := range combined[typeURL] {
				changes.add(typeURL, name, current[name], entry.previous)
			}
		}
	}

	return changes, nil
}

// reconcileDesiredState coalesces compensation into an unclaimed rollback:
// drop removed resources and net no-ops, and guard other entries by their
// restored API transactions. Cache lock required.
func (resources *rollbackResources) reconcileDesiredState(state *nodeState, typeURL typeurl.Index) {
	for name, entry := range *resources {
		current := state.resources[typeURL][name]
		if current.resource == nil || entry.previousEquals(current.resource) {
			delete(*resources, name)
		} else if entry.expectedTransaction != current.transaction {
			entry.expectedTransaction = current.transaction
			(*resources)[name] = entry
		}
	}
}

// mergeHistory folds a newer, independently owned rollback into an
// older unsent one. The oldest previous value remains the rollback target,
// while the newest expected transaction fences the combined rollback. A desired
// removal discards its unsent chain before a later upsert starts another.
func (resources *rollbackResources) mergeHistory(state *nodeState, typeURL typeurl.Index, newer rollbackResources) rollbackResources {
	older := *resources
	if len(newer) == 0 {
		return older
	}
	if older == nil {
		return newer
	}
	for name, newerEntry := range newer {
		if olderEntry, exists := older[name]; exists {
			newerEntry.previous = olderEntry.previous
			if newerEntry.previousEquals(state.resources[typeURL][name].resource) {
				// The new mutation returned this name to the value preceding the
				// unsent chain, so its response rollback is now a no-op.
				delete(older, name)
				continue
			}
		}
		older[name] = newerEntry
	}
	return older
}

func (resources *rollbackResources) resourceRevert(state *nodeState, typeURL typeurl.Index) resourceChanges {
	var changes resourceChanges
	current := state.resources[typeURL]
	for name, entry := range *resources {
		previous := current[name]
		if previous.nonRevertible || previous.transaction != entry.expectedTransaction {
			continue
		}
		// Rebasing a selected inverse can yield identical protobuf contents,
		// but its transaction must still be restored with a fresh revision.
		changes.add(typeURL, name, previous, entry.previous)
	}
	return changes
}

func (rb *callerRollback) prepareRevertLocked() resourceChanges {
	state := rb.state
	var changes resourceChanges
	for typeURL := range typeurl.Count {
		current := state.resources[typeURL]
		for name, previous := range rb.inverse.resources(typeURL) {
			entry := current[name]
			// The inverse only contains semantic changes made by transaction.
			// A matching transaction therefore cannot already contain previous.
			if entry.nonRevertible || entry.transaction != rb.transaction {
				continue
			}
			changes.add(typeURL, name, entry, previous)
		}
		if rb.removed != nil {
			for name, previous := range rb.removed.resources(typeURL) {
				// A newer API deletion invalidates the saved claim. A newer live
				// value also wins, even if its transaction would otherwise match.
				// NACK rebasing may have replaced the saved value with absence.
				if current[name].resource == nil && previous.resource != nil {
					changes.add(typeURL, name, resourceEntry{}, previous)
				}
			}
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
// Only inverse targets change; expected transactions do not. No rejection
// history survives beyond these live inverses.
// Caller must hold cacheImpl.mutex.
func (r *rollbackState) rebaseRejected(state *nodeState, typeURL typeurl.Index, rejected rollbackResources) {
	if pending := state.pendingPublication; pending != nil {
		rollback, _ := pending.rollbacks.Get(typeURL)
		for name, rejectedEntry := range rejected {
			entry, exists := rollback[name]
			if exists && !entry.previous.nonRevertible && entry.previous.transaction == rejectedEntry.expectedTransaction {
				entry.previous = rejectedEntry.previous
				rollback[name] = entry
			}
		}
	}
	for rollback := range r.responses.Members() {
		if rollback.typeURL != typeURL {
			continue
		}
		rollback := rollback.resources
		for name, rejectedEntry := range rejected {
			entry, exists := rollback[name]
			if exists && !entry.previous.nonRevertible && entry.previous.transaction == rejectedEntry.expectedTransaction {
				entry.previous = rejectedEntry.previous
				rollback[name] = entry
			}
		}
	}
	for rollback := range r.callers.Members() {
		for _, inverse := range [2]*resources{&rollback.inverse, rollback.removed} {
			if inverse == nil {
				continue
			}
			if inverse.hasSingleton() {
				singleton := &inverse.singleton
				if singleton.typeURL != typeURL {
					continue
				}
				entry, exists := rejected[singleton.name]
				if exists && !singleton.entry.nonRevertible && singleton.entry.transaction == entry.expectedTransaction {
					singleton.entry = entry.previous
				}
				continue
			}
			for name, entry := range rejected {
				previous, exists := inverse.entries[typeURL][name]
				if exists && !previous.nonRevertible && previous.transaction == entry.expectedTransaction {
					inverse.entries[typeURL][name] = entry.previous
				}
			}
		}
	}
}

// removalWaitRevision is used only for absent-name waits. A collected response
// can be delayed before OnStreamResponse records it, so its live inverse must
// fence older absence ACKs too. Unsent upserts were never exposed to Envoy.
func (r *rollbackState) removalWaitRevision(state *nodeState, typeURL typeurl.Index, name string) callbacks.Revision {
	generation := state.typeStates[typeURL].revertGeneration
	for rollback := range r.responses.Members() {
		if rollback.typeURL != typeURL || rollback == state.typeStates[typeURL].unsentRollback {
			continue
		}
		if entry, exists := rollback.resources[name]; exists {
			generation = generation.MaxTransaction(entry.expectedTransaction)
		}
	}
	return generation.Revision()
}

func (entry rollbackEntry) previousEquals(resource cache_types.Resource) bool {
	previous := entry.previous.resource
	return previous == resource ||
		(previous != nil && resource != nil && xds.ResourceEqual(previous, resource))
}

// pruneRemovedResources ends unpublished or unsent recovery for desired removals,
// including those projected as empty CLAs. Caller upsert rollbacks remain
// independently owned.
func (resources *rollbackResources) pruneRemovedResources(state *nodeState, index typeurl.Index) {
	for name := range *resources {
		if state.resources[index][name].resource == nil {
			delete(*resources, name)
		}
	}
}

func (rb *callerRollback) warnDuplicateLocked(action string) {
	rb.cache.logger.Warn("Ignoring duplicate resource update rollback resolution",
		logfields.NodeID, rb.state.nodeID,
		logfields.XDSRollbackGeneration, callbacks.Generation(0).MaxTransaction(rb.transaction),
		logfields.Operation, action)
}

func (rb *responseRollback) warnDuplicateLocked(action string) {
	rb.cache.logger.Warn("Ignoring duplicate resource update rollback resolution",
		logfields.NodeID, rb.state.nodeID,
		logfields.XDSRollbackGeneration, rb.generation,
		logfields.Operation, action)
}
