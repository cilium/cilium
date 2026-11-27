// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"context"
	"net/netip"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

const DNSGCJobInterval = 1 * time.Minute

const dnsGCJobName = "dns-garbage-collector-job"

// This implements some garbage collection and cleanup functions for the NameManager

// doGC cleans up TTL expired entries from the DNS policies. It removes stale or
// undesired entries from the DNS caches.
// This is done for all per-EP DNSCache instances (ep.DNSHistory) with evictions
// (whether due to TTL expiry or overlimit eviction) cascaded into
// ep.DNSZombies. Data in DNSHistory and DNSZombies is further collected into
// the global name/IP set. The data there drives toFQDNs policy via
// NameManager and ToFQDNs selectors. DNSCache entries expire data when the TTL
// elapses and when the entries for a DNS name are above a limit. The data is
// then placed into DNSZombieMappings instances. These rely on the CT GC loop
// to update liveness for each to-delete IP. When an IP is not in-use it is
// finally deleted from the global name/IP set.
func (n *manager) doGC(ctx context.Context) error {
	var (
		GCStart           = time.Now()
		activeConnections = newNameIPSet()
	)
	namesToClean := make(sets.Set[string])
	n.RLock()
	initialNames := n.cache.names()
	n.RUnlock()

	allEndpointNames := make(sets.Set[string])

	// Cleanup each endpoint cache, deferring deletions via DNSZombies.
	endpoints := n.params.EPMgr.GetEndpoints()
	for _, ep := range endpoints {
		allEndpointNames.Insert(ep.DNSHistory.DumpNames().UnsortedList()...)
		epID := ep.StringID()
		if metrics.FQDNActiveNames.IsEnabled() || metrics.FQDNActiveIPs.IsEnabled() {
			countFQDNs, countIPs := ep.DNSHistory.Count()
			if metrics.FQDNActiveNames.IsEnabled() {
				metrics.FQDNActiveNames.WithLabelValues(epID).Set(float64(countFQDNs))
			}
			if metrics.FQDNActiveIPs.IsEnabled() {
				metrics.FQDNActiveIPs.WithLabelValues(epID).Set(float64(countIPs))
			}
		}
		affectedNames := ep.DNSHistory.GC(GCStart, ep.DNSZombies)
		namesToClean = namesToClean.Union(affectedNames)

		alive, dead := ep.DNSZombies.GC()
		if metrics.FQDNAliveZombieConnections.IsEnabled() {
			metrics.FQDNAliveZombieConnections.WithLabelValues(epID).Set(float64(len(alive)))
		}

		// Retain mappings for connections still active in conntrack.
		for _, zombie := range alive {
			for name := range zombie.Names {
				namesToClean.Insert(name)
				activeConnections.add(name, zombie.IP)
			}
		}

		// Dead entries can be deleted outright, without any replacement.
		// Entries here have been evicted from the DNS cache (via .GC due to
		// TTL expiration or overlimit) and are no longer active connections.
		for _, zombie := range dead {
			for name := range zombie.Names {
				namesToClean.Insert(name)
			}
		}

		// Sync endpoint's persisted state if the DNS state changed during this GC run.
		if len(affectedNames) > 0 || len(dead) > 0 {
			ep.SyncEndpointHeaderFile()
		}
	}

	leakedNames := initialNames.Difference(allEndpointNames)
	for name := range leakedNames {
		namesToClean.Insert(name)
	}

	if namesToClean.Len() == 0 {
		return nil
	}

	// Hold the manager lock while reading endpoint caches and retaining global
	// mappings, so concurrent DNS updates cannot be lost.
	n.Lock()
	for _, ep := range endpoints {
		n.updatedCaches.Insert(ep.DNSHistory)
	}
	maybeStaleIPs := n.removeStaleIPs(namesToClean, &activeConnections)
	n.updatedCaches.Clear()
	n.Unlock()

	namesToCleanSlice := namesToClean.UnsortedList()

	metrics.FQDNGarbageCollectorCleanedTotal.Add(float64(len(namesToCleanSlice)))
	namesCount := len(namesToCleanSlice)
	// Limit the amount of info level logging to some sane amount
	if namesCount > 20 {
		// namesToClean is only used for logging after this so we can reslice it in place
		namesToCleanSlice = namesToCleanSlice[:20]
	}
	n.logger.Info(
		"FQDN garbage collector work deleted entries",
		logfields.Controller, dnsGCJobName,
		logfields.LenEntries, namesCount,
		logfields.Entries, strings.Join(namesToCleanSlice, ","),
	)

	// Remove any now-stale ipcache metadata.
	// Need to RLock here so we don't race on re-insertion.
	n.maybeRemoveMetadata(maybeStaleIPs)

	return nil
}

// removeStaleIPs removes candidates not present in any endpoint cache.
// The caller must hold the manager lock so concurrent DNS updates are included.
func (n *manager) removeStaleIPs(names sets.Set[string], alive *nameIPSet) map[string]set.Set[netip.Addr] {
	removed := n.cache.removalCandidates(names, alive)
	for cache := range n.updatedCaches {
		if len(removed) == 0 {
			break
		}
		cache.RemoveKnown(removed)
	}
	n.cache.remove(removed)
	return removed
}

// RestorationNotify implements endpointstate.RestorationNotifier and loads cache state from the restored system:
// - repopulates the cache from the (persisted) endpoint DNS cache and zombies
func (n *manager) RestorationNotify(possibleEndpoints map[uint16]*endpoint.Endpoint) {
	n.Lock()
	defer n.Unlock()

	// Prefill the cache with DNS lookups from restored endpoints. This is needed
	// to maintain continuity of which IPs are allowed. The GC cascade logic
	// below mimics the logic found in the dns-garbage-collector controller.
	// Note: This is TTL aware, and expired data will not be used (e.g. when
	// restoring after a long delay).
	now := time.Now()
	for _, possibleEP := range possibleEndpoints {
		// Upgrades from old ciliums have this nil
		if possibleEP.DNSHistory != nil {
			if names, ips := possibleEP.DNSHistory.Count(); names > 0 {
				n.logger.Info("restored DNS history from endpoint",
					logfields.EndpointID, possibleEP.ID,
					logfields.Count, names,
					logfields.NumAddresses, ips)
			}

			// GC any connections that have expired, but propagate it to the zombies
			// list. DNSCache.GC can handle a nil DNSZombies parameter. We use the
			// actual now time because we are checkpointing at restore time.
			possibleEP.DNSHistory.GC(now, possibleEP.DNSZombies)
			n.cache.addFromCache(possibleEP.DNSHistory, possibleEP.DNSHistory.DumpNames())
		}

		if possibleEP.DNSZombies != nil {
			alive, _ := possibleEP.DNSZombies.GC()
			for _, zombie := range alive {
				for name := range zombie.Names {
					n.cache.add(name, zombie.IP)
				}
			}
		}
	}
}
