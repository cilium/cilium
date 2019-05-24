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
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
)

// Notes
// Hack 1: We strip ToCIDRSet rules. These are already dissallowed by our
// validation. We do this to simplify handling our own generated rules.
// StartManageDNSName is called by daemon when we inject the generated rules. By
// stripping ToCIDRSet we make the rule equivalent to what it was before. This is
// inefficient.
// We also rely on this in addRule, where we now keep the newest instance of a
// rule to allow handling policy updates for rules we don't look at, but need to
// retain while generating.

const (
	// generatedLabelNameUUID is the label key for policy rules that contain a
	// ToFQDN section and need to be updated
	generatedLabelNameUUID = "ToFQDN-UUID"
)

// uuidLabelSearchKey is an *extended* label key. This is because .Has
// expects the source:key delimiter to be the labels.PathDelimiter
var uuidLabelSearchKey = labels.LabelSourceCiliumGenerated + labels.PathDelimiter + generatedLabelNameUUID

// RuleGen tracks which rules depend on which DNS names. When DNS updates are
// given to a RuleGen it will emit generated policy rules with DNS IPs inserted
// as toCIDR rules. These correspond to the toFQDN matchName entries and are
// emitted via UpdateSelectors.
// DNS information is cached, respecting TTL.
// Note: When DNS data expires rules are not generated again!
type RuleGen struct {
	lock.Mutex // this guards both maps and their contents

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

func (gen *RuleGen) StartManagerFQDNSelector(selector api.FQDNSelector) (identities []identity.NumericIdentity, existed bool) {

	gen.Mutex.Lock()
	_, exists := gen.allSelectors[selector]
	if exists {
		gen.Mutex.Unlock()
		return nil, true
	}

	// Update names to poll for DNS poller since we now care about this selector.
	if len(selector.MatchName) > 0 {
		gen.namesToPoll[prepareMatchName(selector.MatchName)] = struct{}{}
	}

	gen.allSelectors[selector] = selector.ToRegex()
	_, _, selectorIPMapping := mapSelectorsToIPs(map[api.FQDNSelector]struct{}{selector: {}}, gen.cache)
	gen.Mutex.Unlock()

	var err error

	// Used to track identities which are allocated in calls to
	// AllocateCIDRs. If we for some reason cannot allocate new CIDRs,
	// we have to undo all of our changes and release the identities.
	// This is best effort, as releasing can fail as well.
	usedIdentities := make([]*identity.Identity, 0)
	selectorIdentitySliceMapping := make(map[api.FQDNSelector][]identity.NumericIdentity)

	// Allocate identities for each IPNet and then map to selector
	for selector, selectorIPs := range selectorIPMapping {
		log.WithFields(logrus.Fields{
			"fqdnSelector": selector,
			"ips":          selectorIPs,
		}).Debug("getting identities for IPs associated with FQDNSelector")
		var currentlyAllocatedIdentities []*identity.Identity
		if currentlyAllocatedIdentities, err = ipcache.AllocateCIDRsForIPs(selectorIPs); err != nil {
			cache.ReleaseSlice(context.TODO(), nil, usedIdentities)
			log.WithError(err).WithField("prefixes", selectorIPs).Warn(
				"failed to allocate identities for IPs")
			return
		}
		usedIdentities = append(usedIdentities, currentlyAllocatedIdentities...)
		numIDs := make([]identity.NumericIdentity, 0, len(currentlyAllocatedIdentities))
		for i := range currentlyAllocatedIdentities {
			numIDs = append(numIDs, currentlyAllocatedIdentities[i].ID)
		}
		selectorIdentitySliceMapping[selector] = numIDs
	}

	return selectorIdentitySliceMapping[selector], false
}

func (gen *RuleGen) StopManagerFQDNSelector(selector api.FQDNSelector) {
	gen.Mutex.Lock()
	delete(gen.allSelectors, selector)
	if len(selector.MatchName) > 0 {
		delete(gen.namesToPoll, prepareMatchName(selector.MatchName))
	}
	gen.Mutex.Unlock()
}

// NewRuleGen creates an initialized RuleGen.
// When config.Cache is nil, the global fqdn.DefaultDNSCache is used.
func NewRuleGen(config Config) *RuleGen {

	if config.Cache == nil {
		config.Cache = NewDNSCache(0)
	}

	if config.UpdateSelectors == nil {
		config.UpdateSelectors = func(selectorIPMapping map[api.FQDNSelector][]net.IP, namesMissingIPs []api.FQDNSelector) error {
			return nil
		}
	}

	return &RuleGen{
		config:       config,
		namesToPoll:  make(map[string]struct{}),
		allSelectors: make(map[api.FQDNSelector]*regexp.Regexp),
		cache:        config.Cache,
	}

}

// GetDNSCache returns the DNSCache used by the RuleGen
func (gen *RuleGen) GetDNSCache() *DNSCache {
	return gen.cache
}

// GetDNSNames returns a snapshot of the DNS names managed by this RuleGen
func (gen *RuleGen) GetDNSNames() (dnsNames []string) {
	gen.Lock()
	defer gen.Unlock()

	for name := range gen.namesToPoll {
		dnsNames = append(dnsNames, name)
	}

	return dnsNames
}

// UpdateGenerateDNS inserts the new DNS information into the cache. If the IPs
// have changed for a name, store which rules must be updated in rulesToUpdate,
// regenerate them, and emit via UpdateSelectors.
func (gen *RuleGen) UpdateGenerateDNS(lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) error {
	// Update IPs in gen
	fqdnSelectorsToUpdate, updatedDNSNames := gen.UpdateDNSIPs(lookupTime, updatedDNSIPs)
	for dnsName, IPs := range updatedDNSNames {
		log.WithFields(logrus.Fields{
			"matchName":             dnsName,
			"IPs":                   IPs,
			"fqdnSelectorsToUpdate": fqdnSelectorsToUpdate,
		}).Debug("Updated FQDN with new IPs")
	}

	namesMissingIPs, selectorIPMapping := gen.GenerateSelectorUpdates(fqdnSelectorsToUpdate)
	if len(namesMissingIPs) != 0 {
		log.WithField(logfields.DNSName, namesMissingIPs).
			Debug("No IPs to insert when generating DNS name selected by ToFQDN rule")
	}

	return gen.config.UpdateSelectors(selectorIPMapping, namesMissingIPs)
}

// ForceGenerateDNS unconditionally regenerates all rules that refer to DNS
// names in namesToRegen. These names are FQDNs and toFQDNs.matchPatterns or
// matchNames that match them will cause these rules to regenerate.
func (gen *RuleGen) ForceGenerateDNS(namesToRegen []string) error {
	// Lock needed...?
	affectedFQDNSels := make(map[api.FQDNSelector]struct{}, 0)
	for _, dnsName := range namesToRegen {
		for fqdnSel, fqdnRegEx := range gen.allSelectors {
			if fqdnRegEx.MatchString(dnsName) {
				affectedFQDNSels[fqdnSel] = struct{}{}
			}
		}
	}

	namesMissingIPs, selectorIPMapping := gen.GenerateSelectorUpdates(affectedFQDNSels)
	if len(namesMissingIPs) != 0 {
		log.WithField(logfields.DNSName, namesMissingIPs).
			Debug("No IPs to insert when generating DNS name selected by ToFQDN rule")
	}

	// emit the new rules
	return gen.config.
		UpdateSelectors(selectorIPMapping, namesMissingIPs)
}

func (gen *RuleGen) CompleteBootstrap() {
	gen.Lock()
	gen.bootstrapCompleted = true
	gen.Unlock()
}

// UpdateDNSIPs updates the IPs for each DNS name in updatedDNSIPs.
// It returns:
// affectedRules: a list of rule UUIDs that were affected by the new IPs (lookup in .allRules)
// updatedNames: a map of DNS names to all the valid IPs we store for each.
func (gen *RuleGen) UpdateDNSIPs(lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) (affectedSelectors map[api.FQDNSelector]struct{}, updatedNames map[string][]net.IP) {
	updatedNames = make(map[string][]net.IP, len(updatedDNSIPs))
	affectedSelectors = make(map[api.FQDNSelector]struct{}, len(updatedDNSIPs))

	gen.Lock()
	defer gen.Unlock()

perDNSName:
	for dnsName, lookupIPs := range updatedDNSIPs {
		updated := gen.updateIPsForName(lookupTime, dnsName, lookupIPs.IPs, lookupIPs.TTL)

		// The IPs didn't change. No more to be done for this dnsName
		if !updated && gen.bootstrapCompleted {
			log.WithFields(logrus.Fields{
				"dnsName":   dnsName,
				"lookupIPs": lookupIPs,
			}).Debug("IPs didn't change for DNS name")
			continue perDNSName
		}

		// record the IPs that were different
		updatedNames[dnsName] = lookupIPs.IPs

		// accumulate the new selectors affected by new IPs
		for fqdnSel, fqdnRegex := range gen.allSelectors {
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
func (gen *RuleGen) GenerateSelectorUpdates(fqdnSelectors map[api.FQDNSelector]struct{}) (namesMissingIPs []api.FQDNSelector, selectorIPMapping map[api.FQDNSelector][]net.IP) {
	gen.Lock()
	defer gen.Unlock()

	_, namesMissingIPs, selectorIPMapping = mapSelectorsToIPs(fqdnSelectors, gen.cache)
	return namesMissingIPs, selectorIPMapping
}

// updateIPsName will update the IPs for dnsName. It always retains a copy of
// newIPs.
// updated is true when the new IPs differ from the old IPs
func (gen *RuleGen) updateIPsForName(lookupTime time.Time, dnsName string, newIPs []net.IP, ttl int) (updated bool) {
	cacheIPs := gen.cache.Lookup(dnsName)

	if gen.config.MinTTL > ttl {
		ttl = gen.config.MinTTL
	}

	gen.cache.Update(lookupTime, dnsName, newIPs, ttl)
	sortedNewIPs := gen.cache.Lookup(dnsName) // DNSCache returns IPs sorted

	// The 0 checks below account for an unlike race condition where this
	// function is called with already expired data and if other cache data
	// from before also expired.
	return (len(cacheIPs) == 0 && len(sortedNewIPs) == 0) || !sortedIPsAreEqual(sortedNewIPs, cacheIPs)
}
