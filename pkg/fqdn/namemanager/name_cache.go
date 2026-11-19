// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"iter"
	"net/netip"
	"regexp"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/fqdn"
)

// nameCache holds the name manager's global mappings. Mutations go through its
// methods so additional indexes can be maintained here. The manager lock
// protects access; endpoint DNS caches own expiration times.
type nameCache struct {
	entries nameIPSet
}

func newNameCache() nameCache {
	return nameCache{entries: newNameIPSet()}
}

func (s *nameCache) add(name string, ips ...netip.Addr) bool {
	return s.entries.add(name, ips...)
}

func (s *nameCache) all() iter.Seq2[string, []netip.Addr] {
	return func(yield func(string, []netip.Addr) bool) {
		for name, addresses := range s.entries.byName {
			if !yield(name, addresses.AsSlice()) {
				return
			}
		}
	}
}

func (s *nameCache) lookup(name string) []netip.Addr {
	return s.entries.byName[name].AsSlice()
}

func (s *nameCache) has(name string, ip netip.Addr) bool {
	return s.entries.byName[name].Has(ip)
}

func (s *nameCache) lookupByRegexp(pattern *regexp.Regexp) map[string][]netip.Addr {
	matches := make(map[string][]netip.Addr)
	for name, addresses := range s.entries.byName {
		if pattern.MatchString(name) {
			matches[name] = addresses.AsSlice()
		}
	}
	return matches
}

func (s *nameCache) names() sets.Set[string] {
	names := sets.New[string]()
	for name := range s.entries.byName {
		names.Insert(name)
	}
	return names
}

func (s *nameCache) addFromCache(cache *fqdn.DNSCache, names sets.Set[string]) {
	for name := range names {
		s.add(name, cache.Lookup(name)...)
	}
}

// removalCandidates collects existing pairs absent from the live zombies.
// Endpoint caches must rule out candidates before they can be removed.
func (s *nameCache) removalCandidates(names sets.Set[string], alive *nameIPSet) map[string]set.Set[netip.Addr] {
	removed := make(map[string]set.Set[netip.Addr])
	for name := range names {
		addresses := s.entries.byName[name]
		liveIPs := alive.byName[name]
		var candidates set.Set[netip.Addr]
		for ip := range addresses.Members() {
			if !liveIPs.Has(ip) {
				candidates.Insert(ip)
			}
		}
		if !candidates.Empty() {
			removed[name] = candidates
		}
	}
	return removed
}

func (s *nameCache) remove(removed map[string]set.Set[netip.Addr]) {
	for name, ips := range removed {
		addresses := s.entries.byName[name]
		for ip := range ips.Members() {
			addresses.Remove(ip)
		}
		if addresses.Empty() {
			delete(s.entries.byName, name)
		} else {
			s.entries.byName[name] = addresses
		}
	}
}
