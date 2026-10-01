// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/cilium/cilium/pkg/container/set"
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
	// strictRefs is allocated only for strict ADS nodes when a mutation first
	// touches LDS/RDS or CDS/EDS consistency. Nodes start empty, so the index
	// also starts empty and is maintained only through validated mutations.
	strictRefs *strictReferenceCounts
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

// strictReferenceCounts indexes the children referenced by the desired LDS and
// CDS resources. Strict ADS checks only names touched by a transaction; the
// index starts empty and is updated alongside committed resources.
type strictReferenceCounts struct {
	routes    map[string]int
	endpoints map[string]int
}

type strictConsistencyCandidate struct {
	referenceDelta int
	resource       cache_types.Resource
	// A nil resource denotes removal, so it cannot also indicate that the
	// transaction left this child untouched.
	changed bool
}

type strictConsistencyChanges struct {
	routes    map[string]strictConsistencyCandidate
	endpoints map[string]strictConsistencyCandidate
}

// strictParentReferences matches go-control-plane's GetResourceReferences,
// including default filter chains and embedded scoped routes. A set deduplicates
// references within one parent and keeps the common single reference inline,
// without building the upstream extractor's nested maps on every mutation.
func strictParentReferences(parent cache_types.Resource, childTypeURL typeurl.Index) set.Set[string] {
	var refs set.Set[string]
	switch parent := parent.(type) {
	case *cluster.Cluster:
		if childTypeURL == typeurl.Endpoint && parent.GetType() == cluster.Cluster_EDS {
			name := parent.GetEdsClusterConfig().GetServiceName()
			if name == "" {
				name = parent.GetName()
			}
			refs.Insert(name)
		}
	case *listener.Listener:
		if childTypeURL != typeurl.Route {
			return refs
		}
		addChain := func(chain *listener.FilterChain) {
			for _, filter := range chain.GetFilters() {
				config := envoy_resource.GetHTTPConnectionManager(filter)
				if config == nil {
					continue
				}
				if name := config.GetRds().GetRouteConfigName(); name != "" {
					refs.Insert(name)
				}
				for _, scope := range config.GetScopedRoutes().GetScopedRouteConfigurationsList().GetScopedRouteConfigurations() {
					refs.Insert(scope.GetRouteConfigurationName())
				}
			}
		}
		for _, chain := range parent.GetFilterChains() {
			addChain(chain)
		}
		addChain(parent.GetDefaultFilterChain())
	}
	return refs
}

func (changes *strictConsistencyChanges) candidates(childTypeURL typeurl.Index) map[string]strictConsistencyCandidate {
	entries := &changes.routes
	if childTypeURL == typeurl.Endpoint {
		entries = &changes.endpoints
	}
	if *entries == nil {
		*entries = make(map[string]strictConsistencyCandidate)
	}
	return *entries
}

func (changes *strictConsistencyChanges) add(change resourceChange) {
	var childTypeURL typeurl.Index
	switch change.typeURL {
	case typeurl.Listener:
		childTypeURL = typeurl.Route
	case typeurl.Cluster:
		childTypeURL = typeurl.Endpoint
	case typeurl.Route, typeurl.Endpoint:
		entries := changes.candidates(change.typeURL)
		candidate := entries[change.name]
		candidate.resource, candidate.changed = change.next.resource, true
		entries[change.name] = candidate
		return
	default:
		return
	}
	previous := strictParentReferences(change.previous.resource, childTypeURL)
	next := strictParentReferences(change.next.resource, childTypeURL)
	if previous.Empty() && next.Empty() {
		return
	}
	entries := changes.candidates(childTypeURL)
	for name := range previous.Members() {
		candidate := entries[name]
		candidate.referenceDelta--
		entries[name] = candidate
	}
	for name := range next.Members() {
		candidate := entries[name]
		candidate.referenceDelta++
		entries[name] = candidate
	}
}

func (state *nodeState) validateStrictConsistency(changes resourceChanges) (strictConsistencyChanges, error) {
	// Known nodes begin with no desired resources. Every parent mutation and
	// revert comes through this check, so there is no initial full-cache scan.
	if state.strictRefs == nil {
		state.strictRefs = &strictReferenceCounts{}
	}
	refs := state.strictRefs
	var proposed strictConsistencyChanges
	proposed.add(changes.first)
	for _, change := range changes.more {
		proposed.add(change)
	}

	for name, candidate := range proposed.routes {
		count := refs.routes[name] + candidate.referenceDelta
		if count < 0 {
			return strictConsistencyChanges{}, fmt.Errorf("negative RDS reference count for %q", name)
		}
		resource := state.resources[typeurl.Route][name].resource
		if candidate.changed {
			resource = candidate.resource
		}
		if count == 0 && resource != nil {
			return strictConsistencyChanges{}, fmt.Errorf("orphan RDS resource %q", name)
		}
		if count > 0 && (name == "" || resource == nil) {
			return strictConsistencyChanges{}, fmt.Errorf("missing RDS resource %q", name)
		}
	}

	for name, candidate := range proposed.endpoints {
		count := refs.endpoints[name] + candidate.referenceDelta
		if count < 0 {
			return strictConsistencyChanges{}, fmt.Errorf("negative EDS reference count for %q", name)
		}
		if count > 0 && name == "" {
			return strictConsistencyChanges{}, fmt.Errorf("missing EDS resource %q", name)
		}
		resource := state.resources[typeurl.Endpoint][name].resource
		if candidate.changed {
			resource = candidate.resource
		}
		// Missing CLAs are synthesized at publication. Explicit assignments
		// still require a reference; their names have no special cases.
		if count == 0 && resource != nil {
			return strictConsistencyChanges{}, fmt.Errorf("orphan EDS resource %q", name)
		}
	}
	return proposed, nil
}

func (refs *strictReferenceCounts) apply(changes strictConsistencyChanges, factor int) {
	for name, candidate := range changes.routes {
		if candidate.referenceDelta == 0 {
			continue
		}
		count := refs.routes[name] + factor*candidate.referenceDelta
		if count == 0 {
			delete(refs.routes, name)
		} else {
			if refs.routes == nil {
				refs.routes = make(map[string]int)
			}
			refs.routes[name] = count
		}
	}
	for name, candidate := range changes.endpoints {
		if candidate.referenceDelta == 0 {
			continue
		}
		count := refs.endpoints[name] + factor*candidate.referenceDelta
		if count == 0 {
			delete(refs.endpoints, name)
		} else {
			if refs.endpoints == nil {
				refs.endpoints = make(map[string]int)
			}
			refs.endpoints[name] = count
		}
	}
}
