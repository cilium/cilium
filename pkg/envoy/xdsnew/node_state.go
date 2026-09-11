// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"

	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// nodeState owns desired resources, rollback state and watch tracking for a
// consumer configured at cache construction. It persists even with no resources
// or connected streams. Apart from the immutable nodeID, its fields are protected
// by cacheImpl.mutex.
type nodeState struct {
	nodeID      string
	openWatches nodeWatchState
	// Every successful mutation publishes eagerly, so these generations advance
	// together. Both are retained for completion and rollback bookkeeping.
	resourceGeneration callbacks.Generation
	snapshotGeneration callbacks.Generation
	// resources owns the current desired state, including revision-tagged
	// removal tombstones.
	resources resourceMaps
	rollbacks rollbackState
	// typeStates groups node-local bookkeeping by resource type, separate
	// from the desired resource maps shared with sparse inverse containers.
	typeStates typeurl.Slots[resourceTypeState]
}

// resourceTypeState owns bookkeeping for one node and resource type. Its fields
// are protected by cacheImpl.mutex; the zero value has no rollback ownership.
type resourceTypeState struct {
	// revertGeneration identifies the latest successfully published revert that
	// changed resources of this type, or zero if none. It distinguishes restored
	// contents from earlier identical snapshots and provides a conservative wait
	// generation for absent names without retaining per-name tombstones.
	revertGeneration callbacks.Generation
	rollbacks        resourceRollbackState
}

func (state *nodeState) resourceEntries(typeURL typeurl.Index) map[string]resourceEntry {
	if state == nil {
		return nil
	}
	return state.resources[typeURL]
}

// resourceWaitEntry supplies the latest restoration revision for absent values
// after commitEntry has removed their zero-transaction inverse entries.
func (state *nodeState) resourceWaitEntry(typeURL typeurl.Index, name string) resourceEntry {
	entry := state.resources[typeURL][name]
	if entry.resource == nil && entry.transaction.IsZero() {
		entry.revision = state.typeStates[typeURL].revertGeneration.Revision()
	}
	return entry
}

// prepareResourceMutation records the proposed next generation without changing
// the cache. The caller reserves it under the cache lock only if changes exist.
func (state *nodeState) prepareResourceMutation(mutations ResourceMutations, generation callbacks.Generation) (resourceChanges, typeurl.Set, resources) {
	removeSet := mutations.Removed
	upsertSet := mutations.Upserted
	var changes resourceChanges
	prepareResourceMap(&changes, typeurl.Listener, generation, state.resourceEntries(typeurl.Listener), removeSet.Listeners, upsertSet.Listeners)
	prepareResourceMap(&changes, typeurl.Route, generation, state.resourceEntries(typeurl.Route), removeSet.Routes, upsertSet.Routes)
	prepareResourceMap(&changes, typeurl.Cluster, generation, state.resourceEntries(typeurl.Cluster), removeSet.Clusters, upsertSet.Clusters)
	prepareResourceMap(&changes, typeurl.Endpoint, generation, state.resourceEntries(typeurl.Endpoint), removeSet.Endpoints, upsertSet.Endpoints)
	prepareResourceMap(&changes, typeurl.Secret, generation, state.resourceEntries(typeurl.Secret), removeSet.Secrets, upsertSet.Secrets)
	return changes, changes.typeURLs(), changes.inverse()
}

func (state *nodeState) commitResourceMutation(changes resourceChanges) {
	commit := func(change resourceChange) {
		state.resources.commitEntry(change.typeURL, change.name, change.next)
	}
	if !changes.empty() {
		commit(changes.first)
	}
	for _, change := range changes.more {
		commit(change)
	}
}

// generationForType returns the generation of the snapshot which currently
// represents typeURL. Eager publication makes it the same for every type.
func (state *nodeState) generationForType(typeURL typeurl.Index) callbacks.Generation {
	if state == nil {
		return 0
	}
	_ = typeURL
	return state.snapshotGeneration
}

func (state *nodeState) getResource(typeURL typeurl.Index, resourceName string) cache_types.Resource {
	if state == nil || typeURL >= typeurl.Count {
		return nil
	}
	return state.resources[typeURL][resourceName].resource
}
