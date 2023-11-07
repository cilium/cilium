// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"context"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

const DNSGCJobInterval = 1 * time.Minute

const dnsGCJobName = "dns-garbage-collector-job"

var (
	dnsGCControllerGroup = controller.NewGroup(dnsGCJobName)
)

// This implements some garbage collection and cleanup functions for the NameManager

// GC cleans up TTL expired entries from the DNS policies.
// It removes stale or undesired entries from the DNS caches.
// This is done for all per-EP DNSCache
// instances (ep.DNSHistory) with evictions (whether due to TTL expiry or
// overlimit eviction) cascaded into ep.DNSZombies. Data in DNSHistory and
// DNSZombies is further collected into the global DNSCache instance. The
// data there drives toFQDNs policy via NameManager and ToFQDNs selectors.
// DNSCache entries expire data when the TTL elapses and when the entries for
// a DNS name are above a limit. The data is then placed into
// DNSZombieMappings instances. These rely on the CT GC loop to update
// liveness for each to-delete IP. When an IP is not in-use it is finally
// deleted from the global DNSCache. Until then, each of these IPs is
// inserted into the global cache as a synthetic DNS lookup.
func (n *NameManager) GC(ctx context.Context) error {
	var (
		GCStart = time.Now()

		// activeConnections holds DNSName -> single IP entries that have been
		// marked active by the CT GC. Since we expire in this controller, we
		// give these entries 2 cycles of TTL to allow for timing mismatches
		// with the CT GC.
		activeConnectionsTTL = int(2 * DNSGCJobInterval.Seconds())
		activeConnections    = NewDNSCache(activeConnectionsTTL)
	)
	namesToClean := make(map[string]struct{})

	// Cleanup each endpoint cache, deferring deletions via DNSZombies.
	endpoints := n.config.GetEndpointsDNSInfo()
	for _, ep := range endpoints {
		epID := ep.ID
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
		for _, name := range affectedNames {
			if _, found := namesToClean[name]; !found {
				namesToClean[name] = struct{}{}
			}
		}
		alive, dead := ep.DNSZombies.GC()
		if metrics.FQDNAliveZombieConnections.IsEnabled() {
			metrics.FQDNAliveZombieConnections.WithLabelValues(epID).Set(float64(len(alive)))
		}

		// Alive zombie need to be added to the global cache as name->IP
		// entries.
		//
		// NB: The following  comment is _no longer true_ (see
		// DNSZombies.GC()).  We keep it to maintain the original intention
		// of the code for future reference:
		//    We accumulate the names into namesToClean to ensure that the
		//    original full DNS lookup (name -> many IPs) is expired and
		//    only the active connections (name->single IP) are re-added.
		//    Note: Other DNS lookups may also use an active IP. This is
		//    fine.
		//
		lookupTime := time.Now()
		for _, zombie := range alive {
			for _, name := range zombie.Names {
				if _, found := namesToClean[name]; !found {
					namesToClean[name] = struct{}{}
				}
				activeConnections.Update(lookupTime, name, []netip.Addr{zombie.IP}, activeConnectionsTTL)
			}
		}

		// Dead entries can be deleted outright, without any replacement.
		// Entries here have been evicted from the DNS cache (via .GC due to
		// TTL expiration or overlimit) and are no longer active connections.
		for _, zombie := range dead {
			for _, name := range zombie.Names {
				if _, found := namesToClean[name]; !found {
					namesToClean[name] = struct{}{}
				}
			}
		}
	}

	if len(namesToClean) == 0 {
		return nil
	}

	// Collect DNS data into the global cache. This aggregates all endpoint
	// and existing connection data into one place for use elsewhere.
	// In the case where a lookup occurs in a race with .ReplaceFromCache the
	// result is consistent:
	// - If before, the ReplaceFromCache will use the new data when pulling
	// in from each EP cache.
	// - If after, the normal update process occurs after .ReplaceFromCache
	// releases its locks.
	caches := []*DNSCache{activeConnections}
	for _, ep := range endpoints {
		caches = append(caches, ep.DNSHistory)
	}

	namesToCleanSlice := make([]string, 0, len(namesToClean))
	for name := range namesToClean {
		namesToCleanSlice = append(namesToCleanSlice, name)
	}

	n.cache.ReplaceFromCacheByNames(namesToCleanSlice, caches...)

	metrics.FQDNGarbageCollectorCleanedTotal.Add(float64(len(namesToCleanSlice)))
	_, err := n.ForceGenerateDNS(ctx, namesToCleanSlice)
	namesCount := len(namesToCleanSlice)
	// Limit the amount of info level logging to some sane amount
	if namesCount > 20 {
		// namedsToClean is only used for logging after this so we can reslice it in place
		namesToCleanSlice = namesToCleanSlice[:20]
	}
	log.WithField(logfields.Controller, dnsGCJobName).Infof(
		"FQDN garbage collector work deleted %d name entries: %s", namesCount, strings.Join(namesToCleanSlice, ","))
	return err
}

func (n *NameManager) StartGC(ctx context.Context) {
	n.manager.UpdateController(dnsGCJobName, controller.ControllerParams{
		Group:       dnsGCControllerGroup,
		RunInterval: DNSGCJobInterval,
		DoFunc:      n.GC,
		Context:     ctx,
	})
}

// DeleteDNSLookups force-removes any entries in *all* caches that are not currently actively
// passing traffic.
func (n *NameManager) DeleteDNSLookups(expireLookupsBefore time.Time, matchPatternStr string) error {
	var nameMatcher *regexp.Regexp // nil matches all in our implementation
	if matchPatternStr != "" {
		var err error
		nameMatcher, err = matchpattern.ValidateWithoutCache(matchPatternStr)
		if err != nil {
			return err
		}
	}

	namesToRegen := []string{}

	// Clear any to-delete entries globally
	// Clear any to-delete entries in each endpoint, then update globally to
	// insert any entries that now should be in the global cache (because they
	// provide an IP at the latest expiration time).
	namesToRegen = append(namesToRegen, n.cache.ForceExpire(expireLookupsBefore, nameMatcher)...)
	for _, ep := range n.config.GetEndpointsDNSInfo() {
		namesToRegen = append(namesToRegen, ep.DNSHistory.ForceExpire(expireLookupsBefore, nameMatcher)...)
		n.cache.UpdateFromCache(ep.DNSHistory, nil)

		namesToRegen = append(namesToRegen, ep.DNSZombies.ForceExpire(expireLookupsBefore, nameMatcher)...)
		activeConnections := NewDNSCache(0)
		zombies, _ := ep.DNSZombies.GC()
		lookupTime := time.Now()
		for _, zombie := range zombies {
			namesToRegen = append(namesToRegen, zombie.Names...)
			for _, name := range zombie.Names {
				activeConnections.Update(lookupTime, name, []netip.Addr{zombie.IP}, 0)
			}
		}
		n.cache.UpdateFromCache(activeConnections, nil)
	}

	// Swallow error here; the caller doesn't care if this fails
	n.ForceGenerateDNS(context.TODO(), namesToRegen)
	return nil
}

// RestoreCache loads cache state from the restored system:
// - adds any pre-cached DNS entries
// - repopulates the cache from the (persisted) endpoint DNS cache and zombies
func (n *NameManager) RestoreCache(preCachePath string, restoredEPs []EndpointDNSInfo) {
	// Prefill the cache with the CLI provided pre-cache data. This allows various bridging arrangements during upgrades, or just ensure critical DNS mappings remain.
	if preCachePath != "" {
		log.WithField(logfields.Path, preCachePath).Info("Reading toFQDNs pre-cache data")
		precache, err := readPreCache(preCachePath)
		if err != nil {
			// FIXME: add a link to the "documented format"
			log.WithError(err).WithField(logfields.Path, preCachePath).Error("Cannot parse toFQDNs pre-cache data. Please ensure the file is JSON and follows the documented format")
			// We do not stop the agent here. It is safer to continue with best effort
			// than to enter crash backoffs when this file is broken.
		} else {
			n.cache.UpdateFromCache(precache, nil)
		}
	}

	// Prefill the cache with DNS lookups from restored endpoints. This is needed
	// to maintain continuity of which IPs are allowed. The GC cascade logic
	// below mimics the logic found in the dns-garbage-collector controller.
	// Note: This is TTL aware, and expired data will not be used (e.g. when
	// restoring after a long delay).
	now := time.Now()
	for _, possibleEP := range restoredEPs {
		// Upgrades from old ciliums have this nil
		if possibleEP.DNSHistory != nil {
			n.cache.UpdateFromCache(possibleEP.DNSHistory, []string{})

			// GC any connections that have expired, but propagate it to the zombies
			// list. DNSCache.GC can handle a nil DNSZombies parameter. We use the
			// actual now time because we are checkpointing at restore time.
			possibleEP.DNSHistory.GC(now, possibleEP.DNSZombies)
		}

		if possibleEP.DNSZombies != nil {
			lookupTime := time.Now()
			alive, _ := possibleEP.DNSZombies.GC()
			for _, zombie := range alive {
				for _, name := range zombie.Names {
					n.cache.Update(lookupTime, name, []netip.Addr{zombie.IP}, int(2*DNSGCJobInterval.Seconds()))
				}
			}
		}
	}
}

// readPreCache returns a fqdn.DNSCache object created from the json data at
// preCachePath
func readPreCache(preCachePath string) (cache *DNSCache, err error) {
	data, err := os.ReadFile(preCachePath)
	if err != nil {
		return nil, err
	}

	cache = NewDNSCache(0) // no per-host limit here
	if err = cache.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return cache, nil
}
