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

	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
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

type SelectorUpdate struct {
	Added   map[api.FQDNSelector]struct{}
	Deleted map[api.FQDNSelector]struct{}
}

func (gen *RuleGen) UpdateSelectorManagement(selUpdate *SelectorUpdate) error {
	gen.Lock()
	defer gen.Unlock()

	_, _, err := gen.updateDNSResources(selUpdate)
	if err != nil {
		return err
	}

	return nil

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

	namesMissingIPs, selectorIPMapping := gen.GenerateMappingFromSources(fqdnSelectorsToUpdate)
	if len(namesMissingIPs) != 0 {
		log.WithField(logfields.DNSName, namesMissingIPs).
			Debug("No IPs to insert when generating DNS name selected by ToFQDN rule")
	}

	// emit the new rules
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

	namesMissingIPs, selectorIPMapping := gen.GenerateMappingFromSources(affectedFQDNSels)
	if len(namesMissingIPs) != 0 {
		log.WithField(logfields.DNSName, namesMissingIPs).
			Debug("No IPs to insert when generating DNS name selected by ToFQDN rule")
	}

	// emit the new rules
	return gen.config.
		UpdateSelectors(selectorIPMapping, namesMissingIPs)
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

	//perDNSName:
	for dnsName, lookupIPs := range updatedDNSIPs {
		_ = gen.updateIPsForName(lookupTime, dnsName, lookupIPs.IPs, lookupIPs.TTL)

		// The IPs didn't change. No more to be done for this dnsName
		/*if !updated {
			log.WithFields(logrus.Fields{
				"dnsName":   dnsName,
				"lookupIPs": lookupIPs,
			}).Info("UpdateDNSIPs: IPs didn't change")
			continue perDNSName
		}*/

		// record the IPs that were different
		updatedNames[dnsName] = lookupIPs.IPs

		// accumulate the new selectors affected by new IPs
		for fqdnSel, fqdnRegex := range gen.allSelectors {
			matches := fqdnRegex.MatchString(dnsName)
			if matches {
				affectedSelectors[fqdnSel] = struct{}{}
			}
			log.WithFields(logrus.Fields{
				"matches":   matches,
				"fqdnSel":   fqdnSel,
				"dnsName":   dnsName,
				"fqdnRegex": fqdnRegex.String(),
			}).Info("UpdateDNSIPs: fqdnSel matches returned")
		}
	}

	return affectedSelectors, updatedNames
}

// GenerateRulesFromSources creates new api.Rule instances with all ToFQDN
// targets resolved to IPs. The IPs are in generated CIDRSet rules in the
// ToCIDRSet section. Pre-existing rules in ToCIDRSet are preserved
// Note: GenerateRulesFromSources will make a copy of each sourceRule
func (gen *RuleGen) GenerateMappingFromSources(fqdnSelectors map[api.FQDNSelector]struct{}) (namesMissingIPs []api.FQDNSelector, selectorIPMapping map[api.FQDNSelector][]net.IP) {
	gen.Lock()
	defer gen.Unlock()

	_, namesMissingIPs, selectorIPMapping = mapSelectorsToIPs(fqdnSelectors, gen.cache)
	return namesMissingIPs, selectorIPMapping
}

func (gen *RuleGen) updateDNSResources(selUpdate *SelectorUpdate) (newDNSNames, oldDNSNames []string, err error) {
	// We need to "expand" the selectors to their string representation
	// (MatchName and MatchPattern).
	namesToStopManaging := make(map[string]struct{})

	for deletedFQDN := range selUpdate.Deleted {
		// DeletedFQDN should always exist here, so if it doesn't exist,
		// possibly emit a warning??
		if _, exists := gen.allSelectors[deletedFQDN]; exists {
			log.WithField("fqdnSelector", deletedFQDN).Debug("removing selector from FQDN subsystem")
			if len(deletedFQDN.MatchName) > 0 {
				dnsName := prepareMatchName(deletedFQDN.MatchName)
				dnsNameAsRE := matchpattern.ToRegexp(dnsName)
				namesToStopManaging[dnsNameAsRE] = struct{}{}
			}
			if len(deletedFQDN.MatchPattern) > 0 {
				dnsPattern := matchpattern.Sanitize(deletedFQDN.MatchPattern)
				dnsPatternAsRE := matchpattern.ToRegexp(dnsPattern)
				namesToStopManaging[dnsPatternAsRE] = struct{}{}
			}
			delete(gen.allSelectors, deletedFQDN)
		} else {
			log.WithField("fqdnSelector", deletedFQDN).
				Warning("FQDNSelector was deleted from policy " +
					"repository, but FQDN subsystem was not aware that it " +
					"existed")
		}
	}

	// Add a dnsname -> rule reference. We track old/new names by the literal
	// value in matchName/Pattern. They are inserted into the sourceRules
	// RegexpMap as regexeps, however, so we can match against them later.
	for addedFQDN := range selUpdate.Added {
		// Update cache of selectors which gen is tracking.
		log.WithField("fqdnSelector", addedFQDN).Debug("adding selector to FQDN subsystem")

		// ToRegex should never be nil because the FQDNSelector has already
		// passed validation.
		gen.allSelectors[addedFQDN] = addedFQDN.ToRegex()

		REsToAddForSelector := map[string]string{}

		if len(addedFQDN.MatchName) > 0 {
			dnsName := prepareMatchName(addedFQDN.MatchName)
			dnsNameAsRE := matchpattern.ToRegexp(dnsName)
			REsToAddForSelector[addedFQDN.MatchName] = dnsNameAsRE
			gen.namesToPoll[dnsName] = struct{}{}
		}

		if len(addedFQDN.MatchPattern) > 0 {
			dnsPattern := matchpattern.Sanitize(addedFQDN.MatchPattern)
			dnsPatternAsRE := matchpattern.ToRegexp(dnsPattern)
			REsToAddForSelector[addedFQDN.MatchPattern] = dnsPatternAsRE
		}

		for policyMatchStr, dnsPatternAsRE := range REsToAddForSelector {
			delete(namesToStopManaging, dnsPatternAsRE) // keep managing this matchName/Pattern
			// check if this is already managed or not
			/*if exists := gen.sourceRules.LookupContainsValue(dnsPatternAsRE, uuid); exists {
				oldDNSNames = append(oldDNSNames, policyMatchStr)
			} else {*/
			// This ToFQDNs.MatchName/Pattern has not been seen before
			newDNSNames = append(newDNSNames, policyMatchStr)
			// Add this egress rule as a dependent on ToFQDNs.MatchPattern, but fixup the literal
			// name so it can work as a regex
			/*if err = gen.sourceRules.Add(dnsPatternAsRE, uuid); err != nil {
				return nil, nil, err
			}*/
			//}
		}
	}

	// Stop managing names/patterns that remain in shouldStopManaging (i.e. not
	// seen when iterating .ToFQDNs rules above). The net result is to remove
	// dnsName -> uuid associations that existed in the older version of the rule
	// with this UUID, but did not re-occur in the new instance.
	// When a dnsName has no uuid associations, we remove it from the poll list
	// outright.
	for dnsName := range namesToStopManaging {
		delete(gen.namesToPoll, dnsName) // A no-op for matchPattern
	}

	return newDNSNames, oldDNSNames, nil
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
