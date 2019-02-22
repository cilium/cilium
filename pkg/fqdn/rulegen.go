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
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
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

	// sourceRules maps dnsNames to a set of rule UUIDs that depend on
	// that dnsName, and drives CIDR rule generation.
	// A lookup on sourceRules is looking for all rule UUIDs that have an exact
	// match or a regex that would match.
	// The UUID -> rule mapping is allRules below.
	sourceRules *regexpmap.RegexpMap

	// allRules is the global source of truth for rules we are managing. It maps
	// UUID to the rule copy.
	allRules map[string][]*api.Rule

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
		config:      config,
		namesToPoll: make(map[string]struct{}),
		sourceRules: regexpmap.NewRegexpMap(),
		allRules:    make(map[string][]*api.Rule),
		cache:       config.Cache,
	}

}

// MarkToFQDNRules adds a tracking label to rules that contain ToFQDN sections.
// The label is used to ensure that the ToFQDN rules are replaced correctly
// when they are regenerated with IPs. It will also include the generated IPs
// (in the ToCIDRSet) section for DNS names already present in the cache.
// NOTE: It edits the rules in-place
func (gen *RuleGen) MarkToFQDNRules(sourceRules []*api.Rule) ([]*api.Rule, []*api.Rule) {
	gen.Lock()
	defer gen.Unlock()
	result := []*api.Rule{}
	toDelete := []*api.Rule{}

	for _, rule := range sourceRules {
		sourceRule := rule.DeepCopy()
		result = append(result, sourceRule)
		uuidOriginal := getRuleUUIDLabel(sourceRule)
		if !hasToFQDN(sourceRule) {
			// @TODO need to validate multiple rules with the same UUID here.
			if uuidOriginal != "" {
				toDelete = append(toDelete, sourceRule)
			}
			continue
		}

		// If the source Rule has the Kubernetes UUID use that instead of a new
		// one.
		key := labels.NewLabel(k8sConst.PolicyLabelUID, "", labels.LabelSourceK8s)
		if !sourceRule.Labels.Has(key.GetExtendedKey()) {
			if !sourceRule.Labels.Has(uuidLabelSearchKey) {
				// add a unique ID that we can use later to replace this rule.
				uuidLabel := generateUUIDLabel()
				sourceRule.Labels = append(sourceRule.Labels, uuidLabel)
			}
		}

		// Strip out toCIDRSet
		// Note: See Hack 1 above. When we generate rules, we add them and this
		// function is called. This avoids accumulating generated toCIDRSet entries.
		stripToCIDRSet(sourceRule)

		// Insert any IPs for this rule from the cache. This is critical to do
		// here, because we only update the rules on a DNS change later.
		// Note: This will cause a needless regexp compile in this function,
		// because the sourceRules RegexpMap hasn't seen the regexp yet
		_, namesMissingIPs := injectToCIDRSetRules(sourceRule, gen.cache, gen.sourceRules)
		if len(namesMissingIPs) != 0 {
			log.WithField(logfields.DNSName, strings.Join(namesMissingIPs, ",")).
				Debug("No IPs to inject on initial rule insert")
		}
	}
	return result, toDelete
}

func (gen *RuleGen) PushRules(sourceRules []*api.Rule, toDeleteRules []*api.Rule) {
	gen.Lock()
	defer gen.Unlock()

	namesAlreadyPresent := []string{}
	newNamesAdded := []string{}

	for _, rule := range toDeleteRules {
		uuidKey := getRuleUUIDLabel(rule)
		delete(gen.allRules, uuidKey)
	}

	newRules := make(map[string][]*api.Rule)
	for _, rule := range sourceRules {
		uuidKey := getRuleUUIDLabel(rule)
		newRules[uuidKey] = append(newRules[uuidKey], rule)
	}

	for uuidKey, rules := range newRules {
		toRemove := []string{}
		oldDNSNames := map[string]bool{}
		oldDNSMatches := map[string]bool{}

		// Retrieve data from old rules if it is present
		oldRules, ok := gen.allRules[uuidKey]
		if ok {
			oldDNSNames, oldDNSMatches = retrieveFQDNData(oldRules)
		}

		newDNSNames, newDNSMatches := retrieveFQDNData(rules)

		for name := range newDNSNames {
			delete(oldDNSNames, name)
			gen.namesToPoll[name] = struct{}{}
			isNewEntry, err := gen.addSourceRule(name, uuidKey)
			if err != nil {
				log.WithError(err).Warnf(
					"Entry '%s' cannot be added into ToFQDN rules",
					name)
				continue
			}

			if isNewEntry {
				newNamesAdded = append(newNamesAdded, name)
			} else {
				namesAlreadyPresent = append(namesAlreadyPresent, name)
			}
		}

		for name := range oldDNSNames {
			toRemove = append(toRemove, name)
		}

		for dnsMatch := range newDNSMatches {
			delete(oldDNSMatches, dnsMatch)
			gen.sourceRules.Add(dnsMatch, uuidKey)

			isNewEntry, err := gen.addSourceRule(dnsMatch, uuidKey)
			if err != nil {
				log.WithError(err).Warnf(
					"DNSMatch '%s' cannot be added into ToFQDN rules",
					dnsMatch)
				continue
			}
			if isNewEntry {
				newNamesAdded = append(newNamesAdded, dnsMatch)
			} else {
				namesAlreadyPresent = append(namesAlreadyPresent, dnsMatch)
			}
		}

		for oldDNSMatch := range oldDNSMatches {
			toRemove = append(toRemove, oldDNSMatch)
		}

		for _, DNSName := range toRemove {
			if gen.removeFromDNSName(DNSName, uuidKey) {
				delete(gen.namesToPoll, DNSName) // A no-op for matchPattern
			}
		}
		gen.allRules[uuidKey] = rules
	}

	if len(newNamesAdded) > 0 {
		log.WithFields(logrus.Fields{
			"newDNSNames":           newNamesAdded,
			"alreadyExistsDNSNames": namesAlreadyPresent,
			"numRules":              len(sourceRules),
		}).Debug("Added FQDN to managed list")
	}
}

func (gen *RuleGen) addSourceRule(reStr string, lookupValue string) (bool, error) {
	exists := gen.sourceRules.LookupContainsValue(reStr, lookupValue)
	if exists {
		return false, nil
	}
	err := gen.sourceRules.Add(reStr, lookupValue)
	return true, err
}

func retrieveFQDNData(sourceRules []*api.Rule) (map[string]bool, map[string]bool) {
	dnsNames := map[string]bool{}
	dnsMatches := map[string]bool{}

	for _, rule := range sourceRules {
		for _, egressRule := range rule.Egress {

			for _, ToFQDN := range egressRule.ToFQDNs {
				if len(ToFQDN.MatchName) > 0 {
					dnsName := prepareMatchName(ToFQDN.MatchName)
					dnsNameAsRE := matchpattern.ToRegexp(dnsName)
					dnsNames[dnsName] = true
					dnsMatches[dnsNameAsRE] = true
				}
				if len(ToFQDN.MatchPattern) > 0 {
					dnsPattern := matchpattern.Sanitize(ToFQDN.MatchPattern)
					dnsPatternAsRE := matchpattern.ToRegexp(dnsPattern)
					dnsMatches[dnsPatternAsRE] = true
				}
			}
		}
	}

	return dnsNames, dnsMatches
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
			Debug("No IPs to insert when generating DNS name selected by ToFQDN rule")
	}

	// no new rules to add, do not call AddGeneratedRules below
	if len(generatedRules) == 0 {
		return nil
	}

	// emit the new rules
	return gen.config.AddGeneratedRules(generatedRules)
}

// ForceGenerateDNS unconditionally regenerates all rules that refer to DNS
// names in namesToRegen. These names are FQDNs and toFQDNs.matchPatterns or
// matchNames that match them will cause these rules to regenerate.
func (gen *RuleGen) ForceGenerateDNS(namesToRegen []string) error {
	affectedRulesSet := make(map[string]struct{}, 0)
	for _, dnsName := range namesToRegen {
		for _, uuid := range gen.sourceRules.LookupValues(dnsName) {
			affectedRulesSet[uuid] = struct{}{}
		}
	}

	// Convert the set to a list
	var uuidsToUpdate []string
	for uuid := range affectedRulesSet {
		uuidsToUpdate = append(uuidsToUpdate, uuid)
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
			Debug("No IPs to insert when generating DNS name selected by ToFQDN rule")
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
		rules, ok := gen.allRules[uuid]
		// This may happen if a rule was deleted during, other processing, like the DNS lookups
		if !ok {
			notFoundUUIDs = append(notFoundUUIDs, uuid)
			continue
		}

		sourceRules = append(sourceRules, rules...)
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
		_, namesMissingIPs := injectToCIDRSetRules(newRule, gen.cache, gen.sourceRules)
		for _, missing := range namesMissingIPs {
			namesMissingMap[missing] = struct{}{}
		}

		generatedRules = append(generatedRules, newRule)
	}

	for missing := range namesMissingMap {
		namesMissingIPs = append(namesMissingIPs, missing)
	}
	return generatedRules, namesMissingIPs
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
					noLongerManaged = append(noLongerManaged, ToFQDN.MatchName)
				}
			}

			if len(ToFQDN.MatchPattern) > 0 {
				dnsPattern := matchpattern.Sanitize(ToFQDN.MatchPattern)
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
