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
// in the supplied newEndpoints. A backend is only considered orphaned if it is
// absent from ALL endpoint slices in newEndpoints, so deleting one EndpointSlice
// does not orphan backends that survive in another slice for the same service.
func (cache Cache) Orphans(newEndpoints iter.Seq[Endpoints]) iter.Seq[loadbalancer.L3n4Addr] {
	return func(yield func(loadbalancer.L3n4Addr) bool) {
		// Collect all backends still present across all endpoint slices so a
		// backend surviving in another slice is not wrongly orphaned.
		alive := map[loadbalancer.L3n4Addr]struct{}{}
		var eps []Endpoints
		for ep := range newEndpoints {
			eps = append(eps, ep)
			for epAddr, epBe := range ep.Backends {
				for l4Addr := range epBe.Ports {
					alive[loadbalancer.NewL3n4Addr(l4Addr.Protocol, epAddr, l4Addr.Port, loadbalancer.ScopeExternal)] = struct{}{}
				}
			}
		}

		for _, ep := range eps {
			previous, found := cache[ep.Name]
			if !found {
				continue
			}

			for prevAddr, prevBe := range previous.Backends {
				for l4Addr := range prevBe.Ports {
					orphan := loadbalancer.NewL3n4Addr(l4Addr.Protocol, prevAddr, l4Addr.Port, loadbalancer.ScopeExternal)
					if _, stillAlive := alive[orphan]; !stillAlive {
						if !yield(orphan) {
							return
						}
					}
				}
			}
		}
	}
}
