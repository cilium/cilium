// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fqdn

import (
	"context"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
)

// fqdnEntry owns a refcount in 'ipEntry' for each IP in 'ips'.
type fqdnEntry struct {
	regexp *regexp.Regexp
	ips    map[string]*ipEntry
}

func (f *fqdnEntry) getIDs() []identity.NumericIdentity {
	IDs := make([]identity.NumericIdentity, 0, len(f.ips))
	for _, entry := range f.ips {
		IDs = append(IDs, entry.id.ID)
	}
	return IDs
}

// ipEntry
type ipEntry struct {
	ip       net.IP
	refcount uint
	id       *identity.Identity
}

// NameManager maintains state DNS names, via FQDNSelector or exact match for
// polling, need to be tracked. It is the main structure which relates the FQDN
// subsystem to the policy subsystem for plumbing the relation between a DNS
// name and the corresponding IPs which have been returned via DNS lookups.
// When DNS updates are given to a NameManager it update cached selectors as
// required via UpdateSelectors.
// DNS information is cached, respecting TTL.
type NameManager struct {
	lock.Mutex

	// config is a copy from when this instance was initialized.
	// It is read-only once set
	config Config

	// namesToPoll is the set of names that need to be polled. These do not
	// include regexes, as those are not polled directly.
	namesToPoll map[string]struct{}

	// allSelectors contains all FQDNSelectors which are present in all policy. We
	// use these selectors to map selectors --> IPs.
	allSelectors map[api.FQDNSelectorString]fqdnEntry

	// cache is a private copy of the pointer from config.
	cache *DNSCache

	// IDs is a map of identities allocated for IPs. Each selector in 'allSelectors' owns a refcount in each ipEntry it maps
	// key is net.IP.String()
	idMap map[string]*ipEntry

	bootstrapCompleted bool
}

// GetModel returns the API model of the NameManager.
func (n *NameManager) GetModel() *models.NameManager {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	namesToPoll := make([]string, 0, len(n.namesToPoll))
	for name := range n.namesToPoll {
		namesToPoll = append(namesToPoll, name)
	}

	allSelectors := make([]*models.SelectorEntry, 0, len(n.allSelectors))
	for k, v := range n.allSelectors {
		pair := &models.SelectorEntry{
			SelectorString: string(k),
			RegexString:    v.regexp.String(),
		}
		allSelectors = append(allSelectors, pair)
	}

	return &models.NameManager{
		DNSPollNames:        namesToPoll,
		FQDNPolicySelectors: allSelectors,
	}
}

// Lock must be held during any calls to RegisterForIdentityUpdatesLocked or
// UnregisterForIdentityUpdatesLocked.
func (n *NameManager) Lock() {
	n.Mutex.Lock()
}

// Unlock must be called after calls to RegisterForIdentityUpdatesLocked or
// UnregisterForIdentityUpdatesLocked are done.
func (n *NameManager) Unlock() {
	n.Mutex.Unlock()
}

func (n *NameManager) allocateID(ip net.IP) *ipEntry {
	key := ip.String()
	entry, exists := n.idMap[key]
	if !exists || entry == nil {
		id, err := ipcache.AllocateCIDRForIP(ip)
		if err != nil || id == nil {
			log.WithError(err).Errorf("failed to allocate local identity for IP: %s", key)
			return nil
		}
		entry = &ipEntry{ip: ip, id: id}
		n.idMap[key] = entry
	}
	entry.refcount++
	return entry
}

func (n *NameManager) releaseID(entry *ipEntry) {
	if entry != nil {
		entry.refcount--
		if entry.refcount == 0 {
			ipcache.ReleaseCIDRForIP(entry.ip, entry.id)
			delete(n.idMap, entry.ip.String())
		}
	}
}

// RegisterForIdentityUpdatesLocked exposes this FQDNSelector so that identities
// for IPs contained in a DNS response that matches said selector can be
// propagated back to the SelectorCache via `UpdateFQDNSelector`. All DNS names
// contained within the NameManager's cache are iterated over to see if they match
// the FQDNSelector. All IPs which correspond to the DNS names which match this
// Selector will be returned as CIDR identities, as other DNS Names which have
// already been resolved may match this FQDNSelector.
func (n *NameManager) RegisterForIdentityUpdatesLocked(selector api.FQDNSelector) []identity.NumericIdentity {
	key := selector.MapKey()
	_, exists := n.allSelectors[key]
	if exists {
		log.WithField("fqdnSelector", selector).Warning("FQDNSelector was already registered for updates, returning without any identities")
		return nil
	}

	// Update names to poll for DNS poller since we now care about this selector.
	if len(selector.MatchName) > 0 {
		n.namesToPoll[prepareMatchName(selector.MatchName)] = struct{}{}
	}

	selectorIPs := n.cache.LookupBySelector(selector)
	ipEntries := make(map[string]*ipEntry, len(selectorIPs))

	// Allocate identities for each IPNet and then map to selector
	log.WithFields(logrus.Fields{
		"fqdnSelector": selector,
		"ips":          selectorIPs,
	}).Debug("getting identities for IPs associated with FQDNSelector")

	for _, ip := range selectorIPs {
		ipEntries[ip.String()] = n.allocateID(ip)
	}

	entry := fqdnEntry{regexp: selector.ToRegex(), ips: ipEntries}
	n.allSelectors[key] = entry
	return entry.getIDs()
}

// UnregisterForIdentityUpdatesLocked removes this FQDNSelector from the set of
// FQDNSelectors which are being tracked by the NameManager. No more updates for IPs
// which correspond to said selector are propagated.
func (n *NameManager) UnregisterForIdentityUpdatesLocked(selector api.FQDNSelector) {
	key := selector.MapKey()
	entry, exists := n.allSelectors[key]
	if exists {
		// Release IPs
		for _, ipEntry := range entry.ips {
			n.releaseID(ipEntry)
		}
		delete(n.allSelectors, key)
	}
	if len(selector.MatchName) > 0 {
		delete(n.namesToPoll, prepareMatchName(selector.MatchName))
	}
}

// NewNameManager creates an initialized NameManager.
// When config.Cache is nil, the global fqdn.DefaultDNSCache is used.
func NewNameManager(config Config) *NameManager {

	if config.Cache == nil {
		config.Cache = NewDNSCache(0)
	}

	if config.UpdateSelectors == nil {
		config.UpdateSelectors = func(ctx context.Context, selectorIDs map[api.FQDNSelectorString][]identity.NumericIdentity) (*sync.WaitGroup, error) {
			return &sync.WaitGroup{}, nil
		}
	}

	return &NameManager{
		config:       config,
		namesToPoll:  make(map[string]struct{}),
		allSelectors: make(map[api.FQDNSelectorString]fqdnEntry),
		cache:        config.Cache,
		idMap:        make(map[string]*ipEntry),
	}

}

// GetDNSCache returns the DNSCache used by the NameManager
func (n *NameManager) GetDNSCache() *DNSCache {
	return n.cache
}

// GetDNSNames returns a snapshot of the DNS names managed by this NameManager
func (n *NameManager) GetDNSNames() (dnsNames []string) {
	n.Lock()
	defer n.Unlock()

	for name := range n.namesToPoll {
		dnsNames = append(dnsNames, name)
	}

	return dnsNames
}

// UpdateGenerateDNS inserts the new DNS information into the cache. If the IPs
// have changed for a name, store which rules must be updated in rulesToUpdate,
// regenerate them, and emit via UpdateSelectors.
func (n *NameManager) UpdateGenerateDNS(ctx context.Context, lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) (wg *sync.WaitGroup, err error) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	return n.config.UpdateSelectors(ctx, n.updateDNSIPs(lookupTime, updatedDNSIPs))
}

// ForceGenerateDNS unconditionally updates all selectors refer to DNS
// names in namesToRegen. These names are FQDNs and toFQDNs.matchPatterns or
// matchNames that match them will cause these rules to regenerate.
func (n *NameManager) ForceGenerateDNS(ctx context.Context, namesToRegen []string) (wg *sync.WaitGroup, err error) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()

	affectedSelectors := make(map[api.FQDNSelectorString]fqdnEntry, 0)
	for _, dnsName := range namesToRegen {
		for fqdnSelStr, fqdnSel := range n.allSelectors {
			if fqdnSel.regexp.MatchString(dnsName) {
				affectedSelectors[fqdnSelStr] = fqdnSel
			}
		}
	}

	selectorIDs := make(map[api.FQDNSelectorString][]identity.NumericIdentity, len(affectedSelectors))
	for sel, fqdn := range affectedSelectors {
		selectorIDs[sel] = fqdn.getIDs()
	}

	// Update the selectors
	return n.config.UpdateSelectors(ctx, selectorIDs)
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
func (n *NameManager) updateDNSIPs(lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) map[api.FQDNSelectorString][]identity.NumericIdentity {
	affectedSelectors := make(map[api.FQDNSelectorString]fqdnEntry, len(updatedDNSIPs))

perDNSName:
	for dnsName, lookupIPs := range updatedDNSIPs {
		updated := n.updateIPsForName(lookupTime, dnsName, lookupIPs.IPs, lookupIPs.TTL)

		// The IPs didn't change. No more to be done for this dnsName
		if !updated && n.bootstrapCompleted {
			log.WithFields(logrus.Fields{
				"dnsName":   dnsName,
				"lookupIPs": lookupIPs,
			}).Debug("FQDN: IPs didn't change for DNS name")
			continue perDNSName
		}

		log.WithFields(logrus.Fields{
			"matchName": dnsName,
			"IPs":       lookupIPs,
		}).Debug("Updated FQDN with new IPs")

		// accumulate the selectors affected by new IPs
		if len(n.allSelectors) == 0 {
			log.WithFields(logrus.Fields{
				"dnsName":   dnsName,
				"lookupIPs": lookupIPs,
			}).Debug("FQDN: No selectors registered for updates")
		}
		for fqdnSelStr, fqdnSel := range n.allSelectors {
			if fqdnSel.regexp.MatchString(dnsName) {
				// Allocate IDs for new IPs for this selector
				for _, ip := range lookupIPs.IPs {
					key := ip.String()
					if _, exists := fqdnSel.ips[key]; !exists {
						fqdnSel.ips[key] = n.allocateID(ip)
					}
				}
				affectedSelectors[fqdnSelStr] = fqdnSel
			}
		}
	}

	selectorIDs := make(map[api.FQDNSelectorString][]identity.NumericIdentity, len(affectedSelectors))
	for sel, fqdn := range affectedSelectors {
		selectorIDs[sel] = fqdn.getIDs()
	}

	log.WithFields(logrus.Fields{
		"fqdnSelectorsToUpdate": affectedSelectors,
		"fqdnSelectorIDs":       selectorIDs,
	}).Debug("Selectors to update")

	return selectorIDs
}

// updateIPsName will update the IPs for dnsName. It always retains a copy of
// newIPs.
// updated is true when the new IPs differ from the old IPs
func (n *NameManager) updateIPsForName(lookupTime time.Time, dnsName string, newIPs []net.IP, ttl int) (updated bool) {
	cacheIPs := n.cache.Lookup(dnsName)

	if n.config.MinTTL > ttl {
		ttl = n.config.MinTTL
	}

	n.cache.Update(lookupTime, dnsName, newIPs, ttl)
	sortedNewIPs := n.cache.Lookup(dnsName) // DNSCache returns IPs sorted

	// The 0 checks below account for an unlike race condition where this
	// function is called with already expired data and if other cache data
	// from before also expired.
	return (len(cacheIPs) == 0 && len(sortedNewIPs) == 0) || !sortedIPsAreEqual(sortedNewIPs, cacheIPs)
}
