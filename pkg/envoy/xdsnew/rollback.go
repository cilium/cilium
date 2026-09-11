// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"slices"

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
	cache *cacheImpl
	ctx   context.Context
	// Known nodes persist for the cache's lifetime, so resolution can reuse this
	// reference after resources are removed or streams disconnect.
	state   *nodeState
	typeURL typeurl.Index
	// generation is the response inverse's boundary. For a caller inverse
	// (resources == nil), it stores the original API transaction's generation;
	// only that case converts it back to a TransactionID for the revert guard.
	generation callbacks.Generation
	// A non-nil map owns response recovery, including a temporarily empty map
	// awaiting release after coalescing. Caller recovery uses inverse instead.
	resources rollbackResources
	inverse   resources
}

type rollbackOwnerKey struct {
	name        string
	transaction callbacks.TransactionID
}

type rollbackEntry struct {
	previous resourceEntry
	// expectedTransaction identifies the API change this inverse can undo.
	expectedTransaction callbacks.TransactionID
}

// rollbackResources contains response-owned recovery for one resource type.
// Caller rollback retains the complete API transaction separately.
type rollbackResources map[string]rollbackEntry

// retainUnsentLocked keeps one coalesced rollback for a resource type
// until go-control-plane produces a response carrying the current version.
// Register it before delivery so the response can acquire its inverse even
// when the caller supplied no WaitGroup. A reconnecting client's echoed version
// alone cannot prove which names it received; retain the inverse until an
// actual response establishes acceptance or rejection.
func (r *rollbackState) retainUnsentLocked(c *cacheImpl, state *nodeState, typeURL typeurl.Index, generation callbacks.Generation, rollback rollbackResources, snapshot cache.ResourceSnapshot) {
	nodeID := state.nodeID
	if existing := state.typeStates[typeURL].rollbacks.unsent; existing != nil && (existing.resources != nil || !existing.inverse.empty()) {
		if c.completionCbs.CoalesceUnsentTypeGeneration(nodeID, typeURL, existing.generation, generation, nil) {
			existing.resources = existing.resources.mergeHistory(state, typeURL, rollback)
			existing.resources.pruneUnobservableResources(state, typeURL, snapshot)
			existing.generation = generation
			if len(existing.resources) == 0 && c.completionCbs.DiscardUnsentTypeGeneration(nodeID, typeURL, generation) {
				// The cache lock prevents a response from claiming this unsent
				// generation between coalescing it and discarding it.
				// No observable changes remain for this resource type. Caller
				// rollback retains its independently owned inverse.
				existing.finalizeLocked()
			}
			return
		}
		// A response claimed the existing generation before its callback ran.
		// Leave that lifecycle response-owned and start another unsent chain.
		state.typeStates[typeURL].rollbacks.unsent = nil
	}
	rollback.pruneUnobservableResources(state, typeURL, snapshot)
	if len(rollback) == 0 {
		return
	}

	// Response rollback must outlive the context of the mutation which created
	// it. A later NACK remains actionable after that caller has timed out.
	lifecycle := r.newResponseLocked(c, state, typeURL, generation, rollback)
	c.completionCbs.AddTypeGenerationWithRollback(generation, typeURL, nodeID, lifecycle, nil)
	state.typeStates[typeURL].rollbacks.unsent = lifecycle
}

// claimResponseLocked freezes only resource names represented by this response.
// Unrequested names remain unsent and can coalesce with further mutations,
// including when they were changed in the same API transaction.
func (r *rollbackState) claimResponseLocked(c *cacheImpl, state *nodeState, typeURL typeurl.Index, response cache.Response) {
	nodeID := state.nodeID
	lifecycle := state.typeStates[typeURL].rollbacks.unsent
	if lifecycle == nil || lifecycle.resources == nil {
		return
	}
	resources := lifecycle.resources
	// Full-state wildcard groups need no name map. Named groups (and types
	// without implicit deletion) capture their actual requirements once here.
	if callbacks.ResponseCoversType(response, lifecycle.generation) &&
		(typeURL == typeurl.Listener || typeURL == typeurl.Cluster || typeURL == typeurl.NetworkPolicy || typeURL == typeurl.NetworkPolicyHosts) {
		c.completionCbs.CoalesceUnsentTypeGeneration(nodeID, typeURL, lifecycle.generation, lifecycle.generation, &callbacks.ResourceScope{})
		state.typeStates[typeURL].rollbacks.unsent = nil
		return
	}
	var sent rollbackResources
	var sentGeneration, remainingGeneration callbacks.Generation
	for name, entry := range resources {
		if callbacks.ResponseCoversResource(response, name, entry.expectedTransaction) {
			if sent == nil {
				sent = make(rollbackResources)
			}
			sent[name] = entry
			delete(resources, name)
			sentGeneration = sentGeneration.MaxTransaction(entry.expectedTransaction)
		} else {
			remainingGeneration = remainingGeneration.MaxTransaction(entry.expectedTransaction)
		}
	}
	if len(sent) == 0 {
		return
	}
	if len(resources) == 0 {
		lifecycle.resources = sent
		scope := lifecycle.resourceScope(response)
		c.completionCbs.CoalesceUnsentTypeGeneration(nodeID, typeURL, lifecycle.generation, lifecycle.generation, scope)
		state.typeStates[typeURL].rollbacks.unsent = nil
		return
	}
	oldGeneration := lifecycle.generation
	lifecycle.generation = remainingGeneration
	sentLifecycle := r.newResponseLocked(c, state, typeURL, sentGeneration, sent)
	sentScope := sentLifecycle.resourceScope(response)
	c.completionCbs.PartitionUnsentTypeGeneration(nodeID, typeURL, oldGeneration,
		remainingGeneration, lifecycle, nil, sentGeneration, sentLifecycle, sentScope)
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
		state:      state,
		typeURL:    typeURL,
		generation: generation,
		resources:  resources,
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
		state:      tx.state,
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
func (lifecycle *rollbackLifecycle) finalizeLocked() {
	if lifecycle.resources == nil && lifecycle.inverse.empty() {
		lifecycle.warnDuplicateLocked("finalize")
		return
	}
	state := lifecycle.state
	r := &state.rollbacks
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
		r.release(state, lifecycle.typeURL, responseResources)
	}
}

// Finalize releases the caller-owned rollback state after the enclosing
// transaction succeeds.
func (lifecycle *rollbackLifecycle) Finalize() {
	c := lifecycle.cache
	c.mutex.Lock()
	lifecycle.finalizeLocked()
	c.mutex.Unlock()
}

// Revert restores desired resources after a caller failure or an Envoy NACK.
// Each resource's transaction fences its revert. Its previous value and
// transaction are restored with a fresh revision, fencing ACK waits for restored
// state against older responses. Published snapshots remain immutable; a corrective
// snapshot uses the resulting desired state rather than reinstalling an older
// snapshot. Unrelated later mutations are left unchanged.
// A caller's Revert is terminal regardless of its returned error. Response-owned
// recovery is independent and retains its payload on publication
// failure so a subsequent NACK can retry it.
func (lifecycle *rollbackLifecycle) Revert() error {
	c := lifecycle.cache
	// Compensation must remain possible after the original mutation's caller
	// has timed out. Preserve context values without inheriting cancellation.
	tx := c.beginResourceTransaction(context.WithoutCancel(lifecycle.ctx), lifecycle.state)
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
		if !ok || lifecycle == nil || lifecycle.cache != c || lifecycle.state != state {
			return resourceChanges{}, fmt.Errorf("rollback does not belong to cache node %s", state.nodeID)
		}
	}

	// Compose predecessor chains oldest first, before preparing any changes.
	// This also rebases later caller/response inverses which are not selected:
	// their eventual rollback must not resurrect a rejected predecessor. Rejection
	// is definitive even if publishing this correction subsequently fails.
	for _, rollback := range slices.Backward(rollbacks) {
		lifecycle := rollback.(*rollbackLifecycle)
		if lifecycle.resources != nil {
			r.rebaseRejected(lifecycle.typeURL, lifecycle.resources)
		}
	}

	var changes resourceChanges
	if len(rollbacks) == 1 {
		lifecycle := rollbacks[0].(*rollbackLifecycle)
		if lifecycle.resources == nil && lifecycle.inverse.empty() {
			lifecycle.warnDuplicateLocked("revert")
			return resourceChanges{}, nil
		}
		if lifecycle.resources == nil {
			changes = r.resourceRevertInverse(state, lifecycle.generation.TransactionID(), lifecycle.inverse)
		} else {
			changes = lifecycle.resources.resourceRevert(state, lifecycle.typeURL)
		}
	} else {
		var combined typeurl.Slots[rollbackResources]
		for _, rollback := range rollbacks {
			lifecycle := rollback.(*rollbackLifecycle)
			if lifecycle.resources == nil {
				continue
			}
			typeURL := lifecycle.typeURL
			for name, entry := range lifecycle.resources {
				if state.resources[typeURL][name].transaction != entry.expectedTransaction {
					continue
				}
				if combined[typeURL] == nil {
					combined[typeURL] = make(map[string]rollbackEntry)
				}
				combined[typeURL][name] = entry
			}
		}
		for typeURL := range typeurl.Count {
			current := state.resourceEntries(typeURL)
			for name, entry := range combined[typeURL] {
				changes.add(typeURL, name, current[name], entry.previous)
			}
		}
	}

	return changes, nil
}

// finishRevertLocked consumes terminal callers even on failure, but retains
// failed response recovery. Caller must hold cacheImpl.mutex.
func (r *rollbackState) finishRevertLocked(rollbacks []Rollback, err error) {
	for _, rollback := range rollbacks {
		lifecycle := rollback.(*rollbackLifecycle)
		// All response inverses survive a failed batch. Caller resolution
		// remains terminal even on failure, independently of response ownership.
		if lifecycle.resources != nil {
			if err != nil {
				continue
			}
		} else if lifecycle.inverse.empty() {
			continue
		}
		lifecycle.finalizeLocked()
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
			owners := &state.typeStates[typeURL].rollbacks
			for name := range options.inverse.resources(typeURL) {
				owners.pruneTombstone(state.resources[typeURL], rollbackOwnerKey{name: name, transaction: tx.generation.TransactionID()})
			}
			if len(state.resources[typeURL]) == 0 {
				state.resources[typeURL] = nil
			}
		}
	}
}

func (r *rollbackState) releaseSet(state *nodeState, rollbacks typeurl.Map[rollbackResources]) {
	for typeURL, rollback := range rollbacks.All() {
		r.release(state, typeURL, rollback)
	}
}

// mergeHistory folds a newer, independently owned rollback into an
// older unsent one. The oldest previous value remains the rollback target,
// while the newest expected transaction fences the combined rollback. Ownership
// of a superseded tombstone moves to the newer entry.
func (rollback *rollbackResources) mergeHistory(state *nodeState, typeURL typeurl.Index, newer rollbackResources) rollbackResources {
	older := *rollback
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
	return older
}

func (rollback *rollbackResources) resourceRevert(state *nodeState, typeURL typeurl.Index) resourceChanges {
	var changes resourceChanges
	current := state.resourceEntries(typeURL)
	for name, entry := range *rollback {
		previous := current[name]
		if previous.transaction != entry.expectedTransaction {
			continue
		}
		// Rebasing a selected inverse can yield identical protobuf contents,
		// but its transaction must still be restored with a fresh revision.
		changes.add(typeURL, name, previous, entry.previous)
	}
	return changes
}

func (r *rollbackState) resourceRevertInverse(state *nodeState, transaction callbacks.TransactionID, inverse resources) resourceChanges {
	var changes resourceChanges
	for typeURL := range typeurl.Count {
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
func (r *rollbackState) rebaseRejected(typeURL typeurl.Index, rejected rollbackResources) {
	for lifecycle := range r.responses.Members() {
		if lifecycle.typeURL != typeURL {
			continue
		}
		rollback := lifecycle.resources
		for name, rejectedEntry := range rejected {
			entry, exists := rollback[name]
			if exists && entry.previous.transaction == rejectedEntry.expectedTransaction {
				entry.previous = rejectedEntry.previous
				rollback[name] = entry
			}
		}
	}
	for lifecycle := range r.callers.Members() {
		inverse := &lifecycle.inverse
		if inverse.hasSingleton() {
			singleton := &inverse.singleton
			if singleton.typeURL != typeURL {
				continue
			}
			entry, exists := rejected[singleton.name]
			if exists && singleton.entry.transaction == entry.expectedTransaction {
				singleton.entry = entry.previous
			}
			continue
		}
		for name, entry := range rejected {
			previous, exists := inverse.entries[typeURL][name]
			if exists && previous.transaction == entry.expectedTransaction {
				inverse.entries[typeURL][name] = entry.previous
			}
		}
	}
}

func (r *rollbackState) acquireInverse(state *nodeState, inverse resources, transaction callbacks.TransactionID) {
	for typeURL := range typeurl.Count {
		owners := &state.typeStates[typeURL].rollbacks
		for name := range inverse.resources(typeURL) {
			if state.resources[typeURL][name].resource == nil {
				owners.addOwner(rollbackOwnerKey{name: name, transaction: transaction})
			}
		}
	}
}

func (r *rollbackState) release(state *nodeState, typeURL typeurl.Index, rollback rollbackResources) {
	typeState := &state.typeStates[typeURL]
	typeState.rollbacks.releaseResources(&state.resources[typeURL], rollback)
}

func (r *rollbackState) releaseInverse(state *nodeState, inverse resources, transaction callbacks.TransactionID) {
	for typeURL := range typeurl.Count {
		owners := &state.typeStates[typeURL].rollbacks
		for name := range inverse.resources(typeURL) {
			key := rollbackOwnerKey{name: name, transaction: transaction}
			owners.removeOwner(key)
			owners.pruneTombstone(state.resources[typeURL], key)
		}
		if len(state.resources[typeURL]) == 0 {
			state.resources[typeURL] = nil
		}
	}
}

func (state *resourceRollbackState) addOwner(key rollbackOwnerKey) {
	if state.owners == nil {
		state.owners = make(map[rollbackOwnerKey]uint32)
	}
	state.owners[key]++
}

// removeOwner changes bookkeeping without pruning desired state. Coalescing
// may attach replacement ownership; tombstones are pruned at release boundaries.
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

func (state *resourceRollbackState) releaseResources(resources *map[string]resourceEntry, rollback map[string]rollbackEntry) {
	for name, rollbackEntry := range rollback {
		key := rollbackOwnerKey{name: name, transaction: rollbackEntry.expectedTransaction}
		state.removeOwner(key)
		state.pruneTombstone(*resources, key)
	}
	if len(*resources) == 0 {
		*resources = nil
	}
}

// pruneTombstone leaves live values, newer removals and shared ownership intact.
func (state *resourceRollbackState) pruneTombstone(resources map[string]resourceEntry, key rollbackOwnerKey) {
	entry := resources[key.name]
	if entry.resource == nil && entry.transaction == key.transaction && state.owners[key] == 0 {
		delete(resources, key.name)
	}
}

func (entry rollbackEntry) previousEquals(resource cache_types.Resource) bool {
	previous := entry.previous.resource
	return previous == resource ||
		(previous != nil && resource != nil && xds.ResourceEqual(previous, resource))
}

// SotW omission cannot reject an EDS/RDS/SDS removal. Release its response
// inverse; caller rollback retains separate ownership. Synthesized empty CLAs
// remain observable and therefore retain response recovery.
func (rollback *rollbackResources) pruneUnobservableResources(state *nodeState, index typeurl.Index, snapshot cache.ResourceSnapshot) {
	typeState := &state.typeStates[index]
	for name, entry := range *rollback {
		if callbacks.SnapshotResourceStateIsObservable(snapshot, index, name) {
			continue
		}
		typeState.rollbacks.removeOwner(rollbackOwnerKey{name: name, transaction: entry.expectedTransaction})
		delete(*rollback, name)
		typeState.rollbacks.pruneTombstone(state.resources[index], rollbackOwnerKey{name: name, transaction: entry.expectedTransaction})
	}
	if len(state.resources[index]) == 0 {
		state.resources[index] = nil
	}
}

func (lifecycle *rollbackLifecycle) resourceScope(response cache.Response) *callbacks.ResourceScope {
	var scope *callbacks.ResourceScope
	if lifecycle.resources != nil {
		for name, entry := range lifecycle.resources {
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
		logfields.NodeID, lifecycle.state.nodeID,
		logfields.XDSRollbackGeneration, lifecycle.generation,
		logfields.Operation, action)
}
