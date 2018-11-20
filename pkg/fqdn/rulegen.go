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
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/fqdn/regexpmap"
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
// emitted via AddGeneratedRules.
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

	// previousEmittedIPs are the IPs most recently emitted in generated rules
	// for a DNS name. This map is used to check whether a specific DNS name has
	// IPs different than those already in generated rules.
	// Note: The IP slice is sorted on insert, in updateIPsForName, and should
	// not be reshuffled.
	// Note: Names are turned into FQDNs when stored
	previousEmittedIPs map[string][]net.IP

	// sourceRules maps dnsNames to a set of rule UUIDs that depend on
	// that dnsName, and drives CIDR rule generation.
	// A lookup on sourceRules is looking for all rule UUIDs that have an exact
	// match or a regex that would match.
	// The UUID -> rule mapping is allRules below.
	sourceRules *regexpmap.RegexpMap

	// allRules is the global source of truth for rules we are managing. It maps
	// UUID to the rule copy.
	allRules map[string]*api.Rule

	// cache is a private copy of the pointer from config.
	cache *DNSCache
}

// NewRuleGen creates an initialized RuleGen.
// When config.Cache is nil, the global fqdn.DefaultDNSCache is used.
func NewRuleGen(config Config) *RuleGen {

	if config.Cache == nil {
		config.Cache = DefaultDNSCache
	}

	if config.AddGeneratedRules == nil {
		config.AddGeneratedRules = func(generatedRules []*api.Rule) error { return nil }
	}

	return &RuleGen{
		config:             config,
		namesToPoll:        make(map[string]struct{}),
		previousEmittedIPs: make(map[string][]net.IP),
		sourceRules:        regexpmap.NewRegexpMap(),
		allRules:           make(map[string]*api.Rule),
		cache:              config.Cache,
	}

}

// MarkToFQDNRules adds a tracking label to rules that contain ToFQDN sections.
// The label is used to ensure that the ToFQDN rules are replaced correctly
// when they are regenerated with IPs. It will also include the generated IPs
// (in the ToCIDRSet) section for DNS names already present in the cache.
// NOTE: It edits the rules in-place
func (gen *RuleGen) MarkToFQDNRules(sourceRules []*api.Rule) {
	gen.Lock()
	defer gen.Unlock()

perRule:
	for _, sourceRule := range sourceRules {
		// This rule has already been seen, and has a UUID label OR it has no
		// ToFQDN rules. Do no more processing on it.
		// Note: this label can only come from us. An external rule add or replace
		// would lack the UUID-tagged rule and we would add a new UUID label in
		// this function. Cleanup for existing rules with UUIDs is handled in
		// StopManageDNSName
		if !hasToFQDN(sourceRule) || sourceRule.Labels.Has(uuidLabelSearchKey) {
			continue perRule
		}

		// add a unique ID that we can use later to replace this rule.
		uuidLabel := generateUUIDLabel()
		sourceRule.Labels = append(sourceRule.Labels, uuidLabel)

		// Strip out toCIDRSet
		// Note: See Hack 1 above. When we generate rules, we add them and this
		// function is called. This avoids accumulating generated toCIDRSet entries.
		stripToCIDRSet(sourceRule)

		// update IPs in this rule, best effort, from the cache
		// Note: This will cause a needless regexp compile in tihs function,
		// because the sourceRules RegexpMap hasn't seen the regexp yet
		emitted, _ := injectToCIDRSetRules(sourceRule, gen.cache, gen.sourceRules)
		gen.updateEmittedIPs(emitted)
	}
}

// StartManageDNSName begins managing sourceRules that contain toFQDNs
// sections. When the DNS data of the included matchNames changes, RuleGen will
// emit a replacement rule that contains the IPs for each matchName.
// It only adds rules with the ToFQDN-UUID label, added by MarkToFQDNRules, and
// repeat inserts are effectively no-ops.
func (gen *RuleGen) StartManageDNSName(sourceRules []*api.Rule) error {
	gen.Lock()
	defer gen.Unlock()

perRule:
	for _, sourceRule := range sourceRules {
		// Note: we rely on MarkToFQDNRules to insert this label.
		if !sourceRule.Labels.Has(uuidLabelSearchKey) {
			continue perRule
		}

		// Make a copy to avoid breaking the input rules. Strip ToCIDRSet to avoid
		// re-including IPs we optimistically inserted in MarkToFQDNRules
		sourceRuleCopy := sourceRule.DeepCopy()
		stripToCIDRSet(sourceRuleCopy)

		uuid := getRuleUUIDLabel(sourceRuleCopy)
		newDNSNames, alreadyExistsDNSNames, err := gen.addRule(uuid, sourceRuleCopy)
		if err != nil {
			return err
		}

		// only debug print for new names since this function is called
		// unconditionally, even when we insert generated rules (which aren't new)
		if len(newDNSNames) > 0 {
			log.WithFields(logrus.Fields{
				"newDNSNames":           newDNSNames,
				"alreadyExistsDNSNames": alreadyExistsDNSNames,
				"numRules":              len(sourceRules),
			}).Debug("Added FQDN to managed list")
		}
	}

	return nil
}

// StopManageDNSName runs the bookkeeping to remove each api.Rule from
// corresponding dnsName entries in sourceRules and IPs. When no more rules
// rely on a specific dnsName, we remove it from the maps and stop returning it
// from GetDNSNames, or emitting it when regenerating rules. Only rules
// labelled with a ToFQDN-UUID label are processed (added by MarkToFQDNRules).
// Note: rule deletion in policy.Repository is by label, where the rules must
// have at least the labels in the delete. This means our ToFQDN-UUID label,
// and later ToCIDRSet additions will also be deleted correctly, and no action
// is needed here to remove rules we generated.
func (gen *RuleGen) StopManageDNSName(sourceRules []*api.Rule) {
	gen.Lock()
	defer gen.Unlock()

	for _, sourceRule := range sourceRules {
		// skip unmarked rules, nothing to do
		if !sourceRule.Labels.Has(uuidLabelSearchKey) {
			continue
		}

		uuid := getRuleUUIDLabel(sourceRule)
		noLongerManagedDNSNames := gen.removeRule(uuid, sourceRule)
		log.WithFields(logrus.Fields{
			"noLongerManaged": noLongerManagedDNSNames,
		}).Debug("Removed FQDN from managed list")
	}
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
// regenerate them, and emit via AddGeneratedRules.
func (gen *RuleGen) UpdateGenerateDNS(lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) error {
	// Update IPs in gen
	uuidsToUpdate, updatedDNSNames := gen.UpdateDNSIPs(lookupTime, updatedDNSIPs)
	for dnsName, IPs := range updatedDNSNames {
		log.WithFields(logrus.Fields{
			"matchName":     dnsName,
			"IPs":           IPs,
			"uuidsToUpdate": uuidsToUpdate,
		}).Debug("Updated FQDN with new IPs")
	}

	// Generate a new rule for each sourceRule that needs an update.
	rulesToUpdate, notFoundUUIDs := gen.GetRulesByUUID(uuidsToUpdate)
	if len(notFoundUUIDs) != 0 {
		log.WithField("uuid", strings.Join(notFoundUUIDs, ",")).
			Debug("Did not find all rules during update")
	}
	generatedRules, namesMissingIPs := gen.GenerateRulesFromSources(rulesToUpdate)
	if len(namesMissingIPs) != 0 {
		log.WithField(logfields.DNSName, strings.Join(namesMissingIPs, ",")).
			Warn("Missing IPs for ToFQDN rule")
	}

	// no new rules to add, do not call AddGeneratedRules below
	if len(generatedRules) == 0 {
		return nil
	}

	// emit the new rules
	return gen.config.AddGeneratedRules(generatedRules)
}

// UpdateDNSIPs updates the IPs for each DNS name in updatedDNSIPs.
// It returns:
// affectedRules: a list of rule UUIDs that were affected by the new IPs (lookup in .allRules)
// updatedNames: a map of DNS names to all the valid IPs we store for each.
func (gen *RuleGen) UpdateDNSIPs(lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) (affectedRules []string, updatedNames map[string][]net.IP) {
	updatedNames = make(map[string][]net.IP, len(updatedDNSIPs))
	affectedRulesSet := make(map[string]struct{}, len(updatedDNSIPs))

	gen.Lock()
	defer gen.Unlock()

perDNSName:
	for dnsName, lookupIPs := range updatedDNSIPs {
		updated := gen.updateIPsForName(lookupTime, dnsName, lookupIPs.IPs, lookupIPs.TTL)

		// The IPs didn't change. No more to be done for this dnsName
		if !updated {
			continue perDNSName
		}

		// record the IPs that were different
		updatedNames[dnsName] = lookupIPs.IPs

		// accumulate the rules affected by new IPs, that we need to update with
		// CIDR rules
		for _, uuid := range gen.sourceRules.LookupValues(dnsName) {
			affectedRulesSet[uuid] = struct{}{}
		}
	}

	// Convert the set to a list
	for uuid := range affectedRulesSet {
		affectedRules = append(affectedRules, uuid)
	}

	return affectedRules, updatedNames
}

// GetRulesByUUID returns the sourceRule copies of inserted rules. These are
// the source of truth when generating rules with update IPs.
// sourceRules is the list of *api.Rule objects that were found (i.e. currently
// in the gen and not deleted)
// notFoundUUIDs is the set of UUIDs not found. This can occur when a delete
// races with other operations. It is benign in the sense that if a rule UUID is
// not found, no action further action is needed.
func (gen *RuleGen) GetRulesByUUID(uuids []string) (sourceRules []*api.Rule, notFoundUUIDs []string) {
	gen.Lock()
	defer gen.Unlock()

	for _, uuid := range uuids {
		rule, ok := gen.allRules[uuid]
		// This may happen if a rule was deleted during, other processing, like the DNS lookups
		if !ok {
			notFoundUUIDs = append(notFoundUUIDs, uuid)
			continue
		}

		sourceRules = append(sourceRules, rule)
	}

	return sourceRules, notFoundUUIDs
}

// GenerateRulesFromSources creates new api.Rule instances with all ToFQDN
// targets resolved to IPs. The IPs are in generated CIDRSet rules in the
// ToCIDRSet section. Pre-existing rules in ToCIDRSet are preserved
// Note: GenerateRulesFromSources will make a copy of each sourceRule
func (gen *RuleGen) GenerateRulesFromSources(sourceRules []*api.Rule) (generatedRules []*api.Rule, namesMissingIPs []string) {
	gen.Lock()
	defer gen.Unlock()

	var namesMissingMap = make(map[string]struct{})

	for _, sourceRule := range sourceRules {
		newRule := sourceRule.DeepCopy()
		emittedIPs, namesMissingIPs := injectToCIDRSetRules(newRule, gen.cache, gen.sourceRules)
		for _, missing := range namesMissingIPs {
			namesMissingMap[missing] = struct{}{}
		}
		gen.updateEmittedIPs(emittedIPs)

		generatedRules = append(generatedRules, newRule)
	}

	for missing := range namesMissingMap {
		namesMissingIPs = append(namesMissingIPs, missing)
	}
	return generatedRules, namesMissingIPs
}

// addRule places an api.Rule in the source list for a DNS name.
// uuid must be the unique identifier generated for the ToFQDN-UUID label.
// newDNSNames and oldDNSNames indicate names that were newly added from this
// rule, or that were seen in this rule but were already managed.
// If newDNSNames and oldDNSNames are both empty, the rule was not added to the
// managed list.
func (gen *RuleGen) addRule(uuid string, sourceRule *api.Rule) (newDNSNames, oldDNSNames []string, err error) {
	// if we are updating a rule, track which old dnsNames are removed. We store
	// possible names to stop managing in namesToStopManaging. As we add names
	// from the new rule below, these are cleared.
	namesToStopManaging := make(map[string]struct{})
	if oldRule, exists := gen.allRules[uuid]; exists {
		for _, egressRule := range oldRule.Egress {
			for _, ToFQDN := range egressRule.ToFQDNs {
				if len(ToFQDN.MatchName) > 0 {
					dnsName := prepareMatchName(ToFQDN.MatchName)
					dnsNameAsRE := matchpattern.ToRegexp(dnsName)
					namesToStopManaging[dnsNameAsRE] = struct{}{}
				}
				if len(ToFQDN.MatchPattern) > 0 {
					dnsPattern := prepareMatchPattern(ToFQDN.MatchPattern)
					dnsPatternAsRE := matchpattern.ToRegexp(dnsPattern)
					namesToStopManaging[dnsPatternAsRE] = struct{}{}
				}
			}
		}
	}

	// Always add to allRules
	gen.allRules[uuid] = sourceRule

	// Add a dnsname -> rule reference. We track old/new names by the literal
	// value in matchName/Pattern. They are inserted into the sourceRules
	// RegexpMap as regexeps, however, so we can match against them later.
	for _, egressRule := range sourceRule.Egress {
		for _, ToFQDN := range egressRule.ToFQDNs {
			if len(ToFQDN.MatchName) > 0 {
				dnsName := prepareMatchName(ToFQDN.MatchName)
				dnsNameAsRE := matchpattern.ToRegexp(dnsName)
				delete(namesToStopManaging, dnsNameAsRE) // keep this matchName
				// check if this is already managed or not
				if sourceUUIDs := gen.sourceRules.LookupValues(dnsNameAsRE); len(sourceUUIDs) > 0 {
					oldDNSNames = append(oldDNSNames, ToFQDN.MatchName)
				} else {
					gen.namesToPoll[dnsName] = struct{}{}

					// This ToFQDN.MatchName has not been seen before
					newDNSNames = append(newDNSNames, ToFQDN.MatchName)
					// Add this egress rule as a dependent on dnsName, but fixup the literal
					// name so it can work as a regex
					if err = gen.sourceRules.Add(dnsNameAsRE, uuid); err != nil {
						return nil, nil, err
					}
				}
			}

			if len(ToFQDN.MatchPattern) > 0 {
				dnsPattern := prepareMatchPattern(ToFQDN.MatchPattern)
				dnsPatternAsRE := matchpattern.ToRegexp(dnsPattern)
				delete(namesToStopManaging, dnsPatternAsRE) // keep this matchPattern
				// check if this is already managed or not
				if sourceUUIDs := gen.sourceRules.LookupValues(dnsPatternAsRE); len(sourceUUIDs) > 0 {
					oldDNSNames = append(oldDNSNames, ToFQDN.MatchPattern)
				} else {
					// This ToFQDNs.MatchPattern has not been seen before
					newDNSNames = append(newDNSNames, ToFQDN.MatchPattern)
					// Add this egress rule as a dependent on ToFQDNs.MatchPattern, but fixup the literal
					// name so it can work as a regex
					if err = gen.sourceRules.Add(dnsPatternAsRE, uuid); err != nil {
						return nil, nil, err
					}
				}
			}
		}
	}

	// Stop managing names that were not re-added by deleting them from the IP
	// map Remove references to the uuid that were present in the old rule but
	// not re-added by the new one. This may result in no longer managing the
	// dnsName, if no other rules depend on this dnsName
	for dnsName := range namesToStopManaging {
		if shouldStopManaging := gen.removeFromDNSName(dnsName, uuid); shouldStopManaging {
			delete(gen.namesToPoll, dnsName)
		}
	}

	return newDNSNames, oldDNSNames, nil
}

// removeRule removes an api.Rule from the source rule set for each DNS name,
// and from the IPs if no rules depend on that DNS name.
// uuid must be a unique identifier for the sourceRule
// noLongerManaged indicates that no more rules rely on this DNS target
func (gen *RuleGen) removeRule(uuid string, sourceRule *api.Rule) (noLongerManaged []string) {
	// Always delete from allRules
	delete(gen.allRules, uuid)

	// Delete dnsname -> rule references
	for _, egressRule := range sourceRule.Egress {
		for _, ToFQDN := range egressRule.ToFQDNs {
			if len(ToFQDN.MatchName) > 0 {
				dnsName := prepareMatchName(ToFQDN.MatchName)
				dnsNameAsRE := matchpattern.ToRegexp(dnsName)
				if shouldStopManaging := gen.removeFromDNSName(dnsNameAsRE, uuid); shouldStopManaging {
					delete(gen.namesToPoll, dnsName)
					delete(gen.previousEmittedIPs, dnsName) // also delete from the IP map, no longer managed
					noLongerManaged = append(noLongerManaged, ToFQDN.MatchName)
				}
			}

			if len(ToFQDN.MatchPattern) > 0 {
				dnsPattern := prepareMatchPattern(ToFQDN.MatchPattern)
				dnsPatternAsRE := matchpattern.ToRegexp(dnsPattern)
				if shouldStopManaging := gen.removeFromDNSName(dnsPatternAsRE, uuid); shouldStopManaging {
					noLongerManaged = append(noLongerManaged, ToFQDN.MatchPattern)
				}
			}
		}
	}

	return noLongerManaged
}

// removeFromDNSName removes the uuid from the list attached to a dns name. It
// will clean up gen.sourceRules if needed.
// shouldStopManaging indicates that no more rules rely on this DNS target
func (gen *RuleGen) removeFromDNSName(dnsName, uuid string) (shouldStopManaging bool) {
	// remove the rule from the set of rules that rely on dnsName.
	// Note: this isn't removing dnsName from gen.sourceRules, that is just
	// below.
	return gen.sourceRules.Remove(dnsName, uuid)
}

// updateIPsName will update the IPs for dnsName. It always retains a copy of
// newIPs.
// updated is true when the new IPs differ from the old IPs
func (gen *RuleGen) updateIPsForName(lookupTime time.Time, dnsName string, newIPs []net.IP, ttl int) (updated bool) {
	cacheIPs := gen.cache.Lookup(dnsName)
	oldIPs := gen.previousEmittedIPs[dnsName]

	if gen.config.MinTTL > ttl {
		ttl = gen.config.MinTTL
	}

	gen.cache.Update(lookupTime, dnsName, newIPs, ttl)
	sortedNewIPs := gen.cache.Lookup(dnsName) // DNSCache returns IPs sorted
	return !sortedIPsAreEqual(sortedNewIPs, oldIPs) || !sortedIPsAreEqual(sortedNewIPs, cacheIPs)
}

// updateEmittedIPss stores the IPs per DNS name in previousEmittedIPs. These
// can later be used to check whether IPs have changed and need to be emitted
// again.
func (gen *RuleGen) updateEmittedIPs(emitted map[string][]net.IP) {
	for name, ips := range emitted {
		gen.previousEmittedIPs[name] = ips
	}
}
