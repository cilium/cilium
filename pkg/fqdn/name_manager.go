// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"context"
	"hash/fnv"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sync"

	"github.com/go-openapi/strfmt"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ip"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// NameManager maintains state DNS names, via FQDNSelector or exact match for
// polling, need to be tracked. It is the main structure which relates the FQDN
// subsystem to the policy subsystem for plumbing the relation between a DNS
// name and the corresponding IPs which have been returned via DNS lookups.
// When DNS updates are given to a NameManager it update cached selectors as
// required via UpdateSelectors.
// DNS information is cached, respecting TTL.
type NameManager struct {
	lock.RWMutex

	// config is a copy from when this instance was initialized.
	// It is read-only once set
	config Config

	// allSelectors contains all FQDNSelectors which are present in all policy. We
	// use these selectors to map selectors --> IPs.
	allSelectors map[api.FQDNSelector]*regexp.Regexp

	// cache is a private copy of the pointer from config.
	cache *DNSCache

	bootstrapCompleted bool

	manager *controller.Manager

	// list of locks used as coordination points for name updates
	// see LockName() for details.
	nameLocks []*lock.Mutex
}

// GetModel returns the API model of the NameManager.
func (n *NameManager) GetModel() *models.NameManager {
	n.RWMutex.RLock()
	defer n.RWMutex.RUnlock()

	allSelectors := make([]*models.SelectorEntry, 0, len(n.allSelectors))
	for fqdnSel, regex := range n.allSelectors {
		pair := &models.SelectorEntry{
			SelectorString: fqdnSel.String(),
			RegexString:    regex.String(),
		}
		allSelectors = append(allSelectors, pair)
	}

	return &models.NameManager{
		FQDNPolicySelectors: allSelectors,
	}
}

var (
	DNSSourceLookup     = "lookup"
	DNSSourceConnection = "connection"
)

type NoEndpointIDMatch struct {
	ID string
}

func (e NoEndpointIDMatch) Error() string {
	return "unable to find target endpoint ID: " + e.ID
}

// GetDNSHistoryModel returns API models.DNSLookup copies of DNS data in each
// endpoint's DNSHistory. These are filtered by the specified matchers if
// they are non-empty.
//
// Note that this does *NOT* dump the NameManager's own global DNSCache.
//
// endpointID may be "" in order to get DNS history for all endpoints.
func (n *NameManager) GetDNSHistoryModel(endpointID string, prefixMatcher PrefixMatcherFunc, nameMatcher NameMatcherFunc, source string) (lookups []*models.DNSLookup, err error) {
	eps := n.config.GetEndpointsDNSInfo(endpointID)
	if eps == nil {
		return nil, &NoEndpointIDMatch{ID: endpointID}
	}
	for _, ep := range eps {
		lookupSourceEntries := []*models.DNSLookup{}
		connectionSourceEntries := []*models.DNSLookup{}
		for _, lookup := range ep.DNSHistory.Dump() {
			if !nameMatcher(lookup.Name) {
				continue
			}

			// The API model needs strings
			IPStrings := make([]string, 0, len(lookup.IPs))

			// only proceed if any IP matches the prefix selector
			anIPMatches := false
			for _, ip := range lookup.IPs {
				anIPMatches = anIPMatches || prefixMatcher(ip)
				IPStrings = append(IPStrings, ip.String())
			}
			if !anIPMatches {
				continue
			}

			lookupSourceEntries = append(lookupSourceEntries, &models.DNSLookup{
				Fqdn:           lookup.Name,
				Ips:            IPStrings,
				LookupTime:     strfmt.DateTime(lookup.LookupTime),
				TTL:            int64(lookup.TTL),
				ExpirationTime: strfmt.DateTime(lookup.ExpirationTime),
				EndpointID:     int64(ep.ID64),
				Source:         DNSSourceLookup,
			})
		}

		for _, delete := range ep.DNSZombies.DumpAlive(prefixMatcher) {
			for _, name := range delete.Names {
				if !nameMatcher(name) {
					continue
				}

				connectionSourceEntries = append(connectionSourceEntries, &models.DNSLookup{
					Fqdn:           name,
					Ips:            []string{delete.IP.String()},
					LookupTime:     strfmt.DateTime(delete.AliveAt),
					TTL:            0,
					ExpirationTime: strfmt.DateTime(ep.DNSZombies.nextCTGCUpdate),
					EndpointID:     int64(ep.ID64),
					Source:         DNSSourceConnection,
				})
			}
		}

		switch source {
		case DNSSourceLookup:
			lookups = append(lookups, lookupSourceEntries...)
		case DNSSourceConnection:
			lookups = append(lookups, connectionSourceEntries...)
		default:
			lookups = append(lookups, lookupSourceEntries...)
			lookups = append(lookups, connectionSourceEntries...)
		}
	}

	return lookups, nil
}

// Lock must be held during any calls to RegisterForIPUpdatesLocked or
// UnregisterForIPUpdatesLocked.
// Because the NameManager and SelectorCache have interleaving locks, we
// must ALWAYS lock the NameManager first before locking the SelectorCache.
func (n *NameManager) Lock() {
	n.RWMutex.Lock()
}

// Unlock must be called after calls to RegisterForIPUpdatesLocked or
// UnregisterForIPUpdatesLocked are done.
func (n *NameManager) Unlock() {
	n.RWMutex.Unlock()
}

// RegisterForIPUpdatesLocked exposes this FQDNSelector so that updates to
// IPs for names that this selector maches can be
// propagated back to the SelectorCache via `UpdateFQDNSelector`. All DNS names
// contained within the NameManager's cache are iterated over to see if they match
// the FQDNSelector. All already-existing IPs which correspond to the DNS names
// which match this Selector will be returned so the selector is ready for updates.
//
// Because this method is called by the SelectorCache, we cannot make any calls
// back in to the SelectorCache from this method.
func (n *NameManager) RegisterForIPUpdatesLocked(selector api.FQDNSelector) []netip.Addr {
	_, exists := n.allSelectors[selector]
	if exists {
		log.WithField("fqdnSelector", selector).Warning("FQDNSelector was already registered for updates.")
	} else {
		// This error should never occur since the FQDNSelector has already been
		// validated, but account for it for good measure.
		regex, err := selector.ToRegex()
		if err != nil {
			log.WithError(err).WithField("fqdnSelector", selector).Error("FQDNSelector did not compile to valid regex")
			return nil
		}

		n.allSelectors[selector] = regex
	}

	selectorIPMapping := n.mapSelectorsToIPsLocked(sets.New(selector))

	// We may have skipped inserting these IPs in to the ipcache earlier, if they
	// were not previously selected. Upsert them now.
	n.upsertMetadata(selectorIPMapping[selector])

	return selectorIPMapping[selector]
}

// UnregisterForIPUpdatesLocked removes this FQDNSelector from the set of
// FQDNSelectors which are being tracked by the NameManager. No more updates
// for IPs which correspond to said selector are propagated.
func (n *NameManager) UnregisterForIPUpdatesLocked(selector api.FQDNSelector) {
	delete(n.allSelectors, selector)
}

// NewNameManager creates an initialized NameManager.
// When config.Cache is nil, the global fqdn.DefaultDNSCache is used.
func NewNameManager(config Config) *NameManager {

	if config.Cache == nil {
		config.Cache = NewDNSCache(0)
	}

	if config.UpdateSelectors == nil {
		config.UpdateSelectors = func(ctx context.Context, selectorsToIPs map[api.FQDNSelector][]netip.Addr, _ uint64) *sync.WaitGroup {
			return &sync.WaitGroup{}
		}
	}
	if config.GetEndpointsDNSInfo == nil {
		config.GetEndpointsDNSInfo = func(_ string) []EndpointDNSInfo {
			return nil
		}
	}

	n := &NameManager{
		config:       config,
		allSelectors: make(map[api.FQDNSelector]*regexp.Regexp),
		cache:        config.Cache,
		manager:      controller.NewManager(),
		nameLocks:    make([]*lock.Mutex, option.Config.DNSProxyLockCount),
	}

	for i := range n.nameLocks {
		n.nameLocks[i] = &lock.Mutex{}
	}

	return n
}

// UpdateGenerateDNS inserts the new DNS information into the cache. If the IPs
// have changed for a name they will be reflected in updatedDNSIPs.
func (n *NameManager) UpdateGenerateDNS(ctx context.Context, lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) *sync.WaitGroup {
	n.RWMutex.Lock()
	defer n.RWMutex.Unlock()

	// Update IPs in n
	fqdnSelectorsToUpdate, updatedDNSNames, ipcacheRevision := n.updateDNSIPs(lookupTime, updatedDNSIPs)
	for dnsName, IPs := range updatedDNSNames {
		log.WithFields(logrus.Fields{
			"matchName":             dnsName,
			"IPs":                   IPs,
			"fqdnSelectorsToUpdate": fqdnSelectorsToUpdate,
		}).Debug("Updated FQDN with new IPs")
	}

	selectorIPMapping := n.mapSelectorsToIPsLocked(fqdnSelectorsToUpdate)

	// Update SelectorCache selectors and push changes down in to BPF.
	return n.config.UpdateSelectors(ctx, selectorIPMapping, ipcacheRevision)
}

// ForceGenerateDNS unconditionally regenerates all rules that refer to DNS
// names in namesToRegen. These names are FQDNs and toFQDNs.matchPatterns or
// matchNames that match them will cause these rules to regenerate.
// Note: This is used only when DNS entries are cleaned up, not when new results
// are ingested.
func (n *NameManager) ForceGenerateDNS(ctx context.Context, namesToRegen []string) *sync.WaitGroup {
	n.RWMutex.Lock()
	defer n.RWMutex.Unlock()

	affectedFQDNSels := make(sets.Set[api.FQDNSelector], 0)
	for _, dnsName := range namesToRegen {
		for fqdnSel, fqdnRegEx := range n.allSelectors {
			if fqdnRegEx.MatchString(dnsName) {
				affectedFQDNSels.Insert(fqdnSel)
			}
		}
	}

	selectorIPMapping := n.mapSelectorsToIPsLocked(affectedFQDNSels)

	// Update SelectorCache selectors and push changes down in to BPF.
	return n.config.UpdateSelectors(ctx, selectorIPMapping, 0)
}

func (n *NameManager) CompleteBootstrap() {
	n.Lock()
	n.bootstrapCompleted = true
	n.Unlock()
}

// updateDNSIPs updates the IPs for each DNS name in updatedDNSIPs.
// It returns:
// affectedSelectors: a set of all FQDNSelectors which match DNS Names whose
// corresponding set of IPs has changed.
// updatedNames: a map of DNS names to all the valid IPs we store for each.
// ipcacheRevision: a revision number to pass to WaitForRevision()
func (n *NameManager) updateDNSIPs(lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) (affectedSelectors sets.Set[api.FQDNSelector], updatedNames map[string][]net.IP, ipcacheRevision uint64) {
	updatedNames = make(map[string][]net.IP, len(updatedDNSIPs))
	affectedSelectors = make(sets.Set[api.FQDNSelector], len(updatedDNSIPs))
	addrsToUpsert := sets.Set[netip.Addr]{}

	for dnsName, lookupIPs := range updatedDNSIPs {
		addrs := ip.MustAddrsFromIPs(lookupIPs.IPs)
		updated := n.updateIPsForName(lookupTime, dnsName, addrs, lookupIPs.TTL)

		// The IPs didn't change. No more to be done for this dnsName
		if !updated && n.bootstrapCompleted {
			log.WithFields(logrus.Fields{
				"dnsName":   dnsName,
				"lookupIPs": lookupIPs,
			}).Debug("FQDN: IPs didn't change for DNS name")
			continue
		}

		addrsToUpsert.Insert(addrs...)

		// record the IPs that were different
		updatedNames[dnsName] = lookupIPs.IPs

		// accumulate the new selectors affected by new IPs
		if len(n.allSelectors) == 0 {
			log.WithFields(logrus.Fields{
				"dnsName":   dnsName,
				"lookupIPs": lookupIPs,
			}).Debug("FQDN: No selectors registered for updates")
		}
		for fqdnSel, fqdnRegex := range n.allSelectors {
			matches := fqdnRegex.MatchString(dnsName)
			if matches {
				affectedSelectors.Insert(fqdnSel)
			}
		}
	}

	// If new IPs were detected, and these IPs are selected by selectors,
	// then ensure they have an identity allocated to them via the ipcache.
	//
	// If no selectors care about this name, then skip this step. If any selectors
	// are added later, ipcache insertion will happen then.
	if len(addrsToUpsert) > 0 && affectedSelectors.Len() > 0 {
		ipcacheRevision = n.upsertMetadata(addrsToUpsert.UnsortedList())
	}

	return affectedSelectors, updatedNames, ipcacheRevision
}

// updateIPsName will update the IPs for dnsName. It always retains a copy of
// newIPs.
// updated is true when the new IPs differ from the old IPs
func (n *NameManager) updateIPsForName(lookupTime time.Time, dnsName string, newIPs []netip.Addr, ttl int) (updated bool) {
	oldCacheIPs := n.cache.Lookup(dnsName)

	if n.config.MinTTL > ttl {
		ttl = n.config.MinTTL
	}

	changed := n.cache.Update(lookupTime, dnsName, newIPs, ttl)
	if !changed { // Changed may have false positives, but not false negatives
		return false
	}

	newCacheIPs := n.cache.Lookup(dnsName) // DNSCache returns IPs unsorted

	// The 0 checks below account for an unlike race condition where this
	// function is called with already expired data and if other cache data
	// from before also expired.
	if len(oldCacheIPs) != len(newCacheIPs) || len(oldCacheIPs) == 0 {
		return true
	}

	ip.SortAddrList(oldCacheIPs) // sorts in place
	ip.SortAddrList(newCacheIPs)

	return !slices.Equal(oldCacheIPs, newCacheIPs)
}

var ipcacheResource = ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindDaemon, "", "fqdn-name-manager")

// upsertMetadata adds an entry in the ipcache metadata layer for the set of IPs.
// Returns the ipcache queue revision (to pass to .WaitForRevision()).
func (n *NameManager) upsertMetadata(ips []netip.Addr) uint64 {
	prefixes := make([]netip.Prefix, 0, len(ips))
	for _, ip := range ips {
		prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return n.config.IPCache.UpsertPrefixes(prefixes, source.Generated, ipcacheResource)
}

// maybeRemoveMetadata removes the ipcache metadata from every IP in maybeRemoved,
// as long as that IP is not still in the dns cache.
func (n *NameManager) maybeRemoveMetadata(maybeRemoved sets.Set[netip.Addr]) {
	// Need to take an RLock here so that no DNS updates are processed.
	// Otherwise, we might accidentally remove an IP that is newly inserted.
	n.RWMutex.RLock()
	defer n.RWMutex.RUnlock()

	n.cache.RLock()
	prefixes := make([]netip.Prefix, 0, len(maybeRemoved))
	for ip := range maybeRemoved {
		if !n.cache.ipExistsLocked(ip) {
			prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	n.cache.RUnlock()

	log.WithField(logfields.Prefix, prefixes).Debug("Removing fqdn entry from ipcache metadata layer")
	n.config.IPCache.RemovePrefixes(prefixes, source.Generated, ipcacheResource)
}

// LockName is used to serialize  parallel end-to-end updates to the same name.
//
// It is needed due to some subtleties around NameManager locks and
// policy updates. Specifically, we unlock the NameManager after updates
// are queued to endpoints, but *before* changes are pushed to policy maps.
// So, if a second request comes in during this state, it may encounter
// policy drops until the policy updates are complete.
//
// Serializing on names prevents this.
//
// Rather than having a potentially unbounded set of per-name locks, this
// buckets names in to a set of locks. The lock count is configurable.
func (n *NameManager) LockName(name string) {
	idx := nameLockIndex(name, option.Config.DNSProxyLockCount)
	n.nameLocks[idx].Lock()
}

// UnlockName releases a lock previously acquired by LockName()
func (n *NameManager) UnlockName(name string) {
	idx := nameLockIndex(name, option.Config.DNSProxyLockCount)
	n.nameLocks[idx].Unlock()
}

// nameLockIndex hashes the DNS name to a uint32, then returns that
// mod the bucket count.
func nameLockIndex(name string, cnt int) uint32 {
	h := fnv.New32()
	_, _ = h.Write([]byte(name)) // cannot return error
	return h.Sum32() % uint32(cnt)
}
