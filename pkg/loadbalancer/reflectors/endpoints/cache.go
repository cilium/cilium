// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoints

import (
	"iter"
	"maps"

	"github.com/cilium/cilium/pkg/loadbalancer"

	cslices "github.com/cilium/cilium/pkg/slices"
)

type EndpointsNamespacedName = string

// Cache stores the latest endpoints state seen by a loadbalancer reflector.
// Reflectors use it to update backend state when updating an Endpoints. It is
// especially useful to determine which backends need to be orphaned (see
// [Cache.Orphans]).
type Cache struct {
	// byName indexes all cached endpoint slices by their namespaced name.
	byName map[EndpointsNamespacedName]Endpoints

	// byService indexes cached slice names by service name so that
	// [Cache.Orphans] only scans the slices of the affected service instead
	// of the whole cluster-wide cache.
	byService map[loadbalancer.ServiceName]map[EndpointsNamespacedName]struct{}
}

// IsEmpty returns true if the cache holds no endpoint slices.
func (cache Cache) IsEmpty() bool {
	return len(cache.byName) == 0
}

// Clear removes all endpoint slices from the cache.
func (cache *Cache) Clear() {
	clear(cache.byName)
	clear(cache.byService)
}

// All returns all the elements from the cache as a sequence of service name
// and the corresponding backend addresses essentially "unwrapping" and
// converting the Endpoints object for the caller.
func (cache Cache) All() iter.Seq2[loadbalancer.ServiceName, iter.Seq[loadbalancer.L3n4Addr]] {
	return func(yield func(loadbalancer.ServiceName, iter.Seq[loadbalancer.L3n4Addr]) bool) {
		for _, ev := range cache.byName {
			for addr, be := range ev.Backends {
				if !yield(ev.ServiceName, cslices.MapIter(maps.Keys(be.Ports), func(l4Addr loadbalancer.L4Addr) loadbalancer.L3n4Addr {
					return loadbalancer.NewL3n4Addr(
						l4Addr.Protocol,
						addr,
						l4Addr.Port,
						loadbalancer.ScopeExternal,
					)
				})) {
					return
				}
			}
		}
	}
}

func (cache *Cache) Update(ep Endpoints) {
	if cache.byName == nil {
		cache.byName = map[EndpointsNamespacedName]Endpoints{}
		cache.byService = map[loadbalancer.ServiceName]map[EndpointsNamespacedName]struct{}{}
	}
	if old, ok := cache.byName[ep.Name]; ok {
		// Drop the previous index entries. The slice may have been deleted
		// or, in theory, moved to another service.
		delete(cache.byService[old.ServiceName], ep.Name)
		if len(cache.byService[old.ServiceName]) == 0 {
			delete(cache.byService, old.ServiceName)
		}
		delete(cache.byName, ep.Name)
	}
	if len(ep.Backends) == 0 {
		return
	}
	cache.byName[ep.Name] = ep
	names := cache.byService[ep.ServiceName]
	if names == nil {
		names = map[EndpointsNamespacedName]struct{}{}
		cache.byService[ep.ServiceName] = names
	}
	names[ep.Name] = struct{}{}
}

func (cache *Cache) UpdateMany(endpoints iter.Seq[Endpoints]) {
	for ep := range endpoints {
		cache.Update(ep)
	}
}

// backendAddrs returns the backend addresses of an Endpoints object.
func backendAddrs(ep Endpoints) iter.Seq[loadbalancer.L3n4Addr] {
	return func(yield func(loadbalancer.L3n4Addr) bool) {
		for addr, be := range ep.Backends {
			for l4Addr := range be.Ports {
				if !yield(loadbalancer.NewL3n4Addr(
					l4Addr.Protocol,
					addr,
					l4Addr.Port,
					loadbalancer.ScopeExternal,
				)) {
					return
				}
			}
		}
	}
}

// Orphans returns backend addresses that exist in the cache but are not present
// in the supplied newEndpoints.
//
// All endpoints passed here are expected to target the same service. The cache
// may additionally hold endpoint slices of that service that were not part of
// this batch (slices that did not change); their backends are still current
// and are not reported as orphaned. In particular, a backend referenced by
// multiple endpoint slices is only orphaned once no slice references it
// anymore.
//
// Only the cached slices of the given service are scanned (via the byService
// index), so the cost is proportional to the number of slices of that service
// rather than the number of slices in the whole cluster.
func (cache Cache) Orphans(newEndpoints iter.Seq[Endpoints]) iter.Seq[loadbalancer.L3n4Addr] {
	return func(yield func(loadbalancer.L3n4Addr) bool) {
		var svc loadbalancer.ServiceName
		changed := map[EndpointsNamespacedName]struct{}{}
		present := map[loadbalancer.L3n4Addr]struct{}{}
		for ep := range newEndpoints {
			svc = ep.ServiceName
			changed[ep.Name] = struct{}{}
			for addr := range backendAddrs(ep) {
				present[addr] = struct{}{}
			}
		}

		// Account for the cached slices of this service that were not part of
		// this batch. Their backends are still current.
		for name := range cache.byService[svc] {
			if _, ok := changed[name]; ok {
				continue
			}
			for addr := range backendAddrs(cache.byName[name]) {
				present[addr] = struct{}{}
			}
		}

		// Yield the cached backend addresses of this service that are gone.
		// A backend may be referenced by multiple cached slices, so mark each
		// yielded address as present to avoid duplicates.
		for name := range cache.byService[svc] {
			for addr := range backendAddrs(cache.byName[name]) {
				if _, ok := present[addr]; ok {
					continue
				}
				present[addr] = struct{}{}
				if !yield(addr) {
					return
				}
			}
		}
	}
}
