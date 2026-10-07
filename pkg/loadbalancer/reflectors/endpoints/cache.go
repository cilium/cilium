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
type Cache map[EndpointsNamespacedName]Endpoints

// All returns all the elements from the cache as a sequence of service name
// and the corresponding backend addresses essentially "unwrapping" and
// converting the Endpoints object for the caller.
func (cache Cache) All() iter.Seq2[loadbalancer.ServiceName, iter.Seq[loadbalancer.L3n4Addr]] {
	return func(yield func(loadbalancer.ServiceName, iter.Seq[loadbalancer.L3n4Addr]) bool) {
		for _, ev := range cache {
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

func (cache Cache) Update(ep Endpoints) {
	if len(ep.Backends) == 0 {
		delete(cache, ep.Name)
		return
	}

	cache[ep.Name] = ep
}

func (cache Cache) UpdateMany(endpoints iter.Seq[Endpoints]) {
	for ep := range endpoints {
		cache.Update(ep)
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
func (cache Cache) Orphans(newEndpoints iter.Seq[Endpoints]) iter.Seq[loadbalancer.L3n4Addr] {
	return func(yield func(loadbalancer.L3n4Addr) bool) {
		var svc loadbalancer.ServiceName
		changed := map[EndpointsNamespacedName]struct{}{}
		present := map[loadbalancer.L3n4Addr]struct{}{}
		for ep := range newEndpoints {
			svc = ep.ServiceName
			changed[ep.Name] = struct{}{}
			for addr, be := range ep.Backends {
				for l4Addr := range be.Ports {
					present[loadbalancer.NewL3n4Addr(
						l4Addr.Protocol,
						addr,
						l4Addr.Port,
						loadbalancer.ScopeExternal,
					)] = struct{}{}
				}
			}
		}

		// Account for the cached slices of this service that were not part of
		// this batch. Their backends are still current.
		for name, ep := range cache {
			if ep.ServiceName != svc {
				continue
			}
			if _, ok := changed[name]; ok {
				continue
			}
			for addr, be := range ep.Backends {
				for l4Addr := range be.Ports {
					present[loadbalancer.NewL3n4Addr(
						l4Addr.Protocol,
						addr,
						l4Addr.Port,
						loadbalancer.ScopeExternal,
					)] = struct{}{}
				}
			}
		}

		// Yield the cached backend addresses of this service that are gone.
		// A backend may be referenced by multiple cached slices, so mark each
		// yielded address as present to avoid duplicates.
		for _, ep := range cache {
			if ep.ServiceName != svc {
				continue
			}
			for addr, be := range ep.Backends {
				for l4Addr := range be.Ports {
					l3n4Addr := loadbalancer.NewL3n4Addr(
						l4Addr.Protocol,
						addr,
						l4Addr.Port,
						loadbalancer.ScopeExternal,
					)
					if _, ok := present[l3n4Addr]; ok {
						continue
					}
					present[l3n4Addr] = struct{}{}
					if !yield(l3n4Addr) {
						return
					}
				}
			}
		}
	}
}
