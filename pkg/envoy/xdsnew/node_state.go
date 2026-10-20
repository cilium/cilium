// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"
	"iter"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// nodeState owns desired resources, rollback state and watch tracking for a
// consumer configured at cache construction. It persists even with no resources
// or connected streams. Apart from the immutable nodeID, its fields are protected
// by cacheImpl.mutex.
type nodeState struct {
	nodeID string
	// epoch is the wire-version namespace shared by this node's resource types.
	epoch uint64
	// streams use separate slots for the independently numbered protocol modes.
	streams          [callbacks.StreamModeCount]set.Set[int64]
	openWatches      nodeWatchState
	openDeltaWatches nodeDeltaWatchState
	// resourceGeneration identifies the latest desired state, while
	// snapshotGeneration identifies the state most recently published to Envoy.
	resourceGeneration callbacks.Generation
	snapshotGeneration callbacks.Generation
	// resources owns the current desired state, including revision-tagged
	// removal tombstones.
	resources resourceMaps
	rollbacks rollbackState
	// pendingPublication is non-nil while desired state has unpublished changes
	// or completion bookkeeping awaiting snapshot construction and installation.
	pendingPublication *pendingPublication
	// typeStates groups node-local bookkeeping by resource type, separate
	// from the desired resource maps shared with sparse inverse containers.
	typeStates typeurl.Slots[resourceTypeState]
}

// resourceTypeState owns bookkeeping for one node and resource type. Its fields
// are protected by cacheImpl.mutex; the zero value has no pending changes or
// rollback ownership.
type resourceTypeState struct {
	// revertGeneration identifies the latest committed revert that changed
	// resources of this type, or zero if none. It provides a conservative wait
	// revision for restored absence without retaining per-name tombstones.
	revertGeneration callbacks.Generation
	// generation is the aggregate xDS generation. It also advances for
	// compensation and EDS replay; resource entries retain their revisions for
	// ACK waits and transaction IDs for rollback fencing.
	generation callbacks.Generation
	// reportedEpoch is the greatest epoch from this type's first request.
	reportedEpoch uint64
	// negotiatedEpoch is zero until a watch for this type binds the node epoch.
	negotiatedEpoch uint64
	// changedResourceNames tracks names which may differ from the last published
	// snapshot. Successful publication clears the set while preserving
	// rollback ownership.
	changedResourceNames set.Set[string]
	rollbacks            resourceRollbackState
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

func (state *nodeState) commitResourceMutation(changes resourceChanges, generation callbacks.Generation) {
	commit := func(change resourceChange) {
		state.commitResourceEntry(change.typeURL, change.name, change.next)
		// A revert restores an older value and transaction ID, but both its
		// revision and the aggregate xDS generation advance to this mutation.
		state.typeStates[change.typeURL].generation = generation
	}
	if !changes.empty() {
		commit(changes.first)
	}
	for _, change := range changes.more {
		commit(change)
	}
}

// generationForType returns the pending publication's generation, or the
// published snapshot's generation, which currently represents typeURL.
func (state *nodeState) generationForType(typeURL typeurl.Index) callbacks.Generation {
	if state == nil {
		return 0
	}
	if state.pendingPublication != nil {
		if state.pendingPublication.changedTypeURLs.Has(typeURL) {
			return state.pendingPublication.generation
		}
	}
	return state.snapshotGeneration
}

func (state *nodeState) getResource(typeURL typeurl.Index, resourceName string) cache_types.Resource {
	if state == nil || typeURL >= typeurl.Count {
		return nil
	}
	return state.resources[typeURL][resourceName].resource
}

func (state *nodeState) reconcileChangedResourceNames(changes resourceChanges, published cache.ResourceSnapshot) {
	reconcile := func(change resourceChange) {
		changed := &state.typeStates[change.typeURL].changedResourceNames
		resource := state.resources[change.typeURL][change.name].resource
		var publishedResources map[string]cache_types.ResourceWithTTL
		if published != nil {
			publishedResources = published.GetResourcesAndTTL(change.typeURL.URL())
		}
		publishedResource, publishedExists := publishedResources[change.name]
		if resource == nil {
			if !publishedExists {
				changed.Remove(change.name)
			}
			return
		}
		if publishedExists &&
			(publishedResource.Resource == resource || xds.ResourceEqual(publishedResource.Resource, resource)) {
			changed.Remove(change.name)
		}
	}
	if !changes.empty() {
		reconcile(changes.first)
	}
	for _, change := range changes.more {
		reconcile(change)
	}
}

// hasOpenWatchLocked reports whether a watch can consume unpublished changes.
// Caller must hold cacheImpl.mutex.
func (state *nodeState) hasOpenWatchLocked(typeURLs typeurl.Set) bool {
	for typeURL := range typeURLs.Members() {
		watches, _ := state.openWatches.Get(typeURL)
		if !watches.Empty() {
			return true
		}
		deltaWatches, _ := state.openDeltaWatches.Get(typeURL)
		if !deltaWatches.Empty() {
			return true
		}
	}
	return false
}

func (resources *resourceMaps) changedEndpointResourceNames(previous *ciliumSnapshot, changedClusters, changedEndpoints set.Set[string]) set.Set[string] {
	if changedClusters.Empty() {
		return changedEndpoints
	}
	names := changedEndpoints.Clone()
	previousClusters := previous.resourceGroups[typeurl.Cluster].resources.Items
	for name := range changedClusters.Members() {
		if item, exists := previousClusters[name]; exists {
			cluster, ok := item.Resource.(*cluster.Cluster)
			if ok {
				if oldName := clusterEndpointName(name, cluster); oldName != "" {
					names.Insert(oldName)
				}
			}
		}
		if entry := resources[typeurl.Cluster][name]; entry.resource != nil {
			cluster := typedResource[*cluster.Cluster](entry.resource)
			if newName := clusterEndpointName(name, cluster); newName != "" {
				names.Insert(newName)
			}
		}
	}
	return names
}

// pendingPublication records the generation, affected types and rollback state
// awaiting publication. Desired resources live in nodeState.resources; no
// snapshot is constructed until a matching watch can consume it.
type pendingPublication struct {
	generation callbacks.Generation
	// changedTypeURLs also includes EDS when CDS changes can affect its projection
	// or wire version. watchTypeURLs contains the directly mutated
	// types which justify publication when Envoy has capacity for them.
	changedTypeURLs typeurl.Set
	watchTypeURLs   typeurl.Set
	// Each present type binds pending waits and generations to the published
	// version, including unchanged EDS whose version changes.
	// Nonempty values also supply response-owned rollback state; empty values
	// request version association only (including publications made by a revert).
	// Absent types need neither.
	rollbacks typeurl.Map[rollbackResources]
}

// commitResourceEntry updates desired state and records the name for incremental
// snapshot publication. Caller must hold cacheImpl.mutex.
func (state *nodeState) commitResourceEntry(typeURL typeurl.Index, name string, entry resourceEntry) {
	state.resources.commitEntry(typeURL, name, entry)
	state.typeStates[typeURL].changedResourceNames.Insert(name)
}

// selectEpochLocked negotiates the shared node epoch when this TypeURL is
// first requested. An already negotiated TypeURL reporting the current epoch
// is ordinary stream continuity, not a collision. Caller must hold c.mutex.
func (state *nodeState) selectEpochLocked(typeURL typeurl.Index, versions iter.Seq[string]) error {
	if state.typeStates[typeURL].negotiatedEpoch != 0 {
		return nil
	}
	var reported set.Set[uint64]
	var reportedEpoch uint64
	for version := range versions {
		if epoch, ok := parseXDSEpoch(version); ok {
			reported.Insert(epoch)
			reportedEpoch = max(reportedEpoch, epoch)
		}
	}
	epoch := state.epoch
	if epoch == 0 {
		for epoch = 1; reported.Has(epoch); epoch++ {
		}
	} else if reported.Has(epoch) {
		// Once one TypeURL has already selected the shared node epoch, move past
		// every epoch retained from earlier first requests.
		for index := range typeurl.Count {
			epoch = max(epoch, state.typeStates[index].reportedEpoch)
		}
		epoch = max(epoch, reportedEpoch)
		if epoch == ^uint64(0) {
			// Client versions are untrusted protocol input. Do not wrap into
			// epoch zero or poison the retained negotiation state on failure.
			return fmt.Errorf("xDS epoch space exhausted for node %q", state.nodeID)
		}
		epoch++
	}
	state.epoch = epoch
	state.typeStates[typeURL].reportedEpoch = max(state.typeStates[typeURL].reportedEpoch, reportedEpoch)
	return nil
}

// commitEpochNegotiation records that typeURL and every previously negotiated
// resource type are represented by the snapshot bound to the current node
// epoch. Caller must hold c.mutex after successful snapshot publication.
func (state *nodeState) commitEpochNegotiation(typeURL typeurl.Index) {
	for index := range typeurl.Count {
		if index == typeURL || state.typeStates[index].negotiatedEpoch != 0 {
			state.typeStates[index].negotiatedEpoch = state.epoch
		}
	}
}

// endpointReferencesForSnapshot collects EDS names for replay and missing-CLA
// projection. Reuse one set: match changed Clusters' references against the old
// subscription set before extending it with all current references for projection.
// SotW needs only a group-wide replay decision, not a set of replayed names.
func (state *nodeState) endpointReferencesForSnapshot(previous *ciliumSnapshot, changedEndpoints set.Set[string]) (references set.Set[string], replay bool) {
	oldClusters := previous.resourceGroups[typeurl.Cluster].resources.Items
	for name := range state.typeStates[typeurl.Cluster].changedResourceNames.Members() {
		current := state.resources[typeurl.Cluster][name].resource
		if current == nil {
			continue
		}
		if old, exists := oldClusters[name]; exists && old.Resource == current {
			continue
		}
		endpointName := clusterEndpointName(name, current.(*cluster.Cluster))
		if endpointName == "" {
			continue
		}
		references.Insert(endpointName)
	}
	if !references.Empty() {
		// Envoy may not resubscribe when a new or changed Cluster reuses an EDS
		// name. Match in one pass, not one old-Cluster scan per changed Cluster.
		for name, old := range oldClusters {
			if references.Has(clusterEndpointName(name, old.Resource.(*cluster.Cluster))) {
				replay = true
				break
			}
		}
	}
	for name := range changedEndpoints.Members() {
		if state.resources[typeurl.Endpoint][name].resource != nil {
			continue
		}
		// Only a changed name without an explicit CLA needs the full current
		// reference index. Shared names retain an empty assignment while any
		// Cluster still uses them; removals drop assignments no longer referenced.
		for name, entry := range state.resources[typeurl.Cluster] {
			if endpointName := clusterEndpointName(name, typedResource[*cluster.Cluster](entry.resource)); endpointName != "" {
				references.Insert(endpointName)
			}
		}
		break
	}
	return references, replay
}
