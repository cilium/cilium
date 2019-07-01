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
	"net"
	"regexp"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
)

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
	allSelectors map[api.FQDNSelector]*regexp.Regexp

	// cache is a private copy of the pointer from config.
	cache *DNSCache

	bootstrapCompleted bool
}

// RegisterForIdentityUpdates exposes this FQDNSelector so that identities
// for IPs contained in a DNS response that matches said selector can be
// propagated back to the SelectorCache via `UpdateFQDNSelector`. All DNS names
// contained within the NameManager's cache are iterated over to see if they match
// the FQDNSelector. All IPs which correspond to the DNS names which match this
// Selector will be returned as CIDR identities, as other DNS Names which have
// already been resolved may match this FQDNSelector.
func (n *NameManager) RegisterForIdentityUpdates(selector api.FQDNSelector) []identity.NumericIdentity {

	n.Mutex.Lock()
	_, exists := n.allSelectors[selector]
	if exists {
		log.WithField("fqdnSelector", selector).Error("FQDNSelector was already registered for updates, returning without any identities")
		n.Mutex.Unlock()
		return nil
	}

	// This error should never occur since the FQDNSelector has already been
	// validated, but account for it for good measure.
	regex, err := selector.ToRegex()
	if err != nil {
		log.WithError(err).WithField("fqdnSelector", selector).Error("FQDNSelector did not compile to valid regex")
		n.Mutex.Unlock()
		return nil
	}

	// Update names to poll for DNS poller since we now care about this selector.
	if len(selector.MatchName) > 0 {
		n.namesToPoll[prepareMatchName(selector.MatchName)] = struct{}{}
	}

	n.allSelectors[selector] = regex
	_, selectorIPMapping := mapSelectorsToIPs(map[api.FQDNSelector]struct{}{selector: {}}, n.cache)
	n.Mutex.Unlock()

	// Allocate identities for each IPNet and then map to selector
	selectorIPs := selectorIPMapping[selector]
	log.WithFields(logrus.Fields{
		"fqdnSelector": selector,
		"ips":          selectorIPs,
	}).Debug("getting identities for IPs associated with FQDNSelector")
	var currentlyAllocatedIdentities []*identity.Identity
	if currentlyAllocatedIdentities, err = ipcache.AllocateCIDRsForIPs(selectorIPs); err != nil {
		log.WithError(err).WithField("prefixes", selectorIPs).Warn(
			"failed to allocate identities for IPs")
		return nil
	}
	numIDs := make([]identity.NumericIdentity, 0, len(currentlyAllocatedIdentities))
	for i := range currentlyAllocatedIdentities {
		numIDs = append(numIDs, currentlyAllocatedIdentities[i].ID)
	}

	return numIDs
}

// UnregisterForIdentityUpdates removes this FQDNSelector from the set of
// FQDNSelectors which are being tracked by the NameManager. No more updates for IPs
// which correspond to said selector are propagated.
func (n *NameManager) UnregisterForIdentityUpdates(selector api.FQDNSelector) {
	n.Mutex.Lock()
	delete(n.allSelectors, selector)
	if len(selector.MatchName) > 0 {
		delete(n.namesToPoll, prepareMatchName(selector.MatchName))
	}
	n.Mutex.Unlock()
}

// NewNameManager creates an initialized NameManager.
// When config.Cache is nil, the global fqdn.DefaultDNSCache is used.
func NewNameManager(config Config) *NameManager {

	if config.Cache == nil {
		config.Cache = NewDNSCache(0)
	}

	if config.UpdateSelectors == nil {
		config.UpdateSelectors = func(selectorIPMapping map[api.FQDNSelector][]net.IP, namesMissingIPs []api.FQDNSelector) error {
			return nil
		}
	}

	return &NameManager{
		config:       config,
		namesToPoll:  make(map[string]struct{}),
		allSelectors: make(map[api.FQDNSelector]*regexp.Regexp),
		cache:        config.Cache,
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
func (n *NameManager) UpdateGenerateDNS(lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) error {
	// Update IPs in n
	fqdnSelectorsToUpdate, updatedDNSNames := n.UpdateDNSIPs(lookupTime, updatedDNSIPs)
	for dnsName, IPs := range updatedDNSNames {
		log.WithFields(logrus.Fields{
			"matchName":             dnsName,
			"IPs":                   IPs,
			"fqdnSelectorsToUpdate": fqdnSelectorsToUpdate,
		}).Debug("Updated FQDN with new IPs")
	}

	namesMissingIPs, selectorIPMapping := n.GenerateSelectorUpdates(fqdnSelectorsToUpdate)
	if len(namesMissingIPs) != 0 {
		log.WithField(logfields.DNSName, namesMissingIPs).
			Debug("No IPs to insert when generating DNS name selected by ToFQDN rule")
	}

	return n.config.UpdateSelectors(selectorIPMapping, namesMissingIPs)
}

// ForceGenerateDNS unconditionally regenerates all rules that refer to DNS
// names in namesToRegen. These names are FQDNs and toFQDNs.matchPatterns or
// matchNames that match them will cause these rules to regenerate.
func (n *NameManager) ForceGenerateDNS(namesToRegen []string) error {
	n.Mutex.Lock()
	affectedFQDNSels := make(map[api.FQDNSelector]struct{}, 0)
	for _, dnsName := range namesToRegen {
		for fqdnSel, fqdnRegEx := range n.allSelectors {
			if fqdnRegEx.MatchString(dnsName) {
				affectedFQDNSels[fqdnSel] = struct{}{}
			}
		}
	}

	namesMissingIPs, selectorIPMapping := mapSelectorsToIPs(affectedFQDNSels, n.cache)
	if len(namesMissingIPs) != 0 {
		log.WithField(logfields.DNSName, namesMissingIPs).
			Debug("No IPs to insert when generating DNS name selected by ToFQDN rule")
	}
	n.Mutex.Unlock()

	// emit the new rules
	return n.config.
		UpdateSelectors(selectorIPMapping, namesMissingIPs)
}

func (n *NameManager) CompleteBootstrap() {
	n.Lock()
	n.bootstrapCompleted = true
	n.Unlock()
}

// UpdateDNSIPs updates the IPs for each DNS name in updatedDNSIPs.
// It returns:
// affectedSelectors: a set of all FQDNSelectors which match DNS Names whose
// corresponding set of IPs has changed.
// updatedNames: a map of DNS names to all the valid IPs we store for each.
func (n *NameManager) UpdateDNSIPs(lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) (affectedSelectors map[api.FQDNSelector]struct{}, updatedNames map[string][]net.IP) {
	updatedNames = make(map[string][]net.IP, len(updatedDNSIPs))
	affectedSelectors = make(map[api.FQDNSelector]struct{}, len(updatedDNSIPs))

	n.Lock()
	defer n.Unlock()

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
				affectedSelectors[fqdnSel] = struct{}{}
			}
		}
	}

	return affectedSelectors, updatedNames
}

// GenerateSelectorUpdates iterates over all names in the DNS cache managed by
// gen and figures out to which FQDNSelectors managed by the cache these names
// map. Returns the set of FQDNSelectors which map to no IPs, and a mapping
// of FQDNSelectors to IPs.
func (n *NameManager) GenerateSelectorUpdates(fqdnSelectors map[api.FQDNSelector]struct{}) (namesMissingIPs []api.FQDNSelector, selectorIPMapping map[api.FQDNSelector][]net.IP) {
	n.Lock()
	defer n.Unlock()

	namesMissingIPs, selectorIPMapping = mapSelectorsToIPs(fqdnSelectors, n.cache)
	return namesMissingIPs, selectorIPMapping
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
