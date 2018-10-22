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

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/miekg/dns"

	"github.com/sirupsen/logrus"
)

// Notes
// Hack 1: We strip ToCIDRSet rules. These are already dissallowed by our
// validation. We do this to simplify handling our own generated rules.
// StartPollForDNSName is called by daemon when we inject the generated rules. By
// stripping ToCIDRSet we make the rule equivalent to what it was before. This is
// inefficient.
// We also rely on this in addRule, where we now keep the newest instance of a
// rule to allow handling policy updates for rules we don't look at, but need to
// retain while generating.

const (
	// generatedLabelNameUUID is the label key for policy rules that contain a
	// ToFQDN section and need to be updated
	generatedLabelNameUUID = "ToFQDN-UUID"

	// DNSPollerInterval is the time between 2 complete DNS lookup runs of the
	// DNSPoller controller
	// Note: This cannot be less than 1*time.Second, as it is used as a default
	// for MinTTL in fqdn.Config
	DNSPollerInterval = 5 * time.Second
)

// uuidLabelSearchKey is an *extended* label key. This is because .Has
// expects the source:key delimiter to be the labels.PathDelimiter
var uuidLabelSearchKey = generateUUIDLabel().GetExtendedKey()

// StartDNSPoller spawns a singleton DNS polling controller. The controller
// will, periodically, run a DNS lookup for each ToFQDN target DNS name
// inserted with StartPollForDNSName.
// Note: Repeated calls will replace earlier instances of the controller.
func StartDNSPoller(poller *DNSPoller) {
	log.Debug("Starting DNS poller for ToFQDN rules")
	controller.NewManager().UpdateController("dns-poller", controller.ControllerParams{
		RunInterval: DNSPollerInterval,
		DoFunc:      poller.LookupUpdateDNS,
		StopFunc: func() error {
			log.Debug("Stopping DNS poller for ToFQDN rules")
			return nil
		},
	})
}

// DNSPoller periodically runs lookups for registered DNS names. It will emit
// regenerated policy rules when the IPs change. CNAMEs (and DNAMEs) are not
// handled directly, but will depend on the resolver's behavior.
// fqdn.Config can be opitonally used to set how the DNS lookups are
// executed (via LookupDNSNames) and how generated policy rules are handled
// (via AddGeneratedRules).
type DNSPoller struct {
	lock.Mutex // this guards both maps and their contents

	// config is a copy from when this instance was initialized.
	// It is read-only once set
	config Config

	// IPs maps dnsNames as strings to the most recent IPs seen for them. It is,
	// in effect, a reflection of the realized DNS -> IP state (but acts as a
	// source of information for the CIDR rules we generate)
	// Note: The IP slice is sorted. on insert in updateIPsForName, and should
	// not be reshuffled.
	// Note: Names are turned into FQDNs when stored
	IPs map[string][]net.IP

	// sourceRule maps dnsNames to a set of rule UUIDs that depend on
	// that dnsName. It is the desired state for DNS -> IP data, and drives IPs
	// above, which drives CIDR rule generation.
	// The data here is map[dnsName][rule uuid]struct{} where the inner map acts
	// as a refcount of rules that depend on this dnsName.
	// The UUID -> rule mapping is allRules below.
	sourceRules map[string]map[string]struct{}

	// allRules is the global source of truth for rules we are managing. It maps
	// UUID to the rule copy.
	allRules map[string]*api.Rule

	// cache is a private copy of the pointer from config.
	cache *DNSCache
}

// NewDNSPoller creates an initialized DNSPoller. It does not start the controller (use .Start)
func NewDNSPoller(config Config) *DNSPoller {
	if config.MinTTL == 0 {
		config.MinTTL = 2 * int(DNSPollerInterval/time.Second)
	}

	if config.Cache == nil {
		config.Cache = DefaultDNSCache
	}

	if config.LookupDNSNames == nil {
		config.LookupDNSNames = DNSLookupDefaultResolver
	}

	if config.AddGeneratedRules == nil {
		config.AddGeneratedRules = func(generatedRules []*api.Rule) error { return nil }
	}

	return &DNSPoller{
		config:      config,
		IPs:         make(map[string][]net.IP),
		sourceRules: make(map[string]map[string]struct{}),
		allRules:    make(map[string]*api.Rule),
		cache:       config.Cache,
	}
}

// MarkToFQDNRules adds a tracking label to the rule, if it contains ToFQDN
// rules. The label is used to ensure that the ToFQDN rules are replaced
// correctly when they are regenerated with IPs. It will also include the
// generated ToCIDRSet section for IPs that are in the cache.
// NOTE: It edits the rules in-place
func (poller *DNSPoller) MarkToFQDNRules(sourceRules []*api.Rule) {
	poller.Lock()
	defer poller.Unlock()

perRule:
	for _, sourceRule := range sourceRules {
		// This rule has already been seen, and has a UUID label OR it has no
		// ToFQDN rules. Do no more processing on it.
		// Note: this label can only come from us. An external rule add or replace
		// would lack the UUID-tagged rule and we would add a new UUID label in
		// this function. Cleanup for existing rules with UUIDs is handled in
		// StopPollForDNSName
		if !hasToFQDN(sourceRule) || sourceRule.Labels.Has(uuidLabelSearchKey) {
			continue perRule
		}

		// add a unique ID that we can use later to replace this rule.
		uuidLabel := generateUUIDLabel()
		sourceRule.Labels = append(sourceRule.Labels, uuidLabel)

		// Inject initial IPs in this rule, best effort from the cache
		injectToCIDRSetRules(sourceRule, poller.IPs)
	}
}

// StartPollForDNSName sets up the polling for ToFQDN rules in each api.Rule.
// It only adds rules with the ToFQDN-UUID label, added by MarkToFQDNRules, and
// repeat inserts are effectively no-ops.
func (poller *DNSPoller) StartPollForDNSName(sourceRules []*api.Rule) {
	poller.Lock()
	defer poller.Unlock()

perRule:
	for _, sourceRule := range sourceRules {
		// Note: we rely on this reject to enforce calling stripToCIDRSet
		// in MarkToFQDNRules
		if !sourceRule.Labels.Has(uuidLabelSearchKey) {
			continue perRule
		}

		// Make a copy to avoid breaking the input rules. Strip ToCIDRSet to avoid
		// accumulating anything we included during MarkToFQDNRules
		sourceRuleCopy := sourceRule.DeepCopy()
		stripToCIDRSet(sourceRuleCopy)

		uuid := getRuleUUIDLabel(sourceRuleCopy)
		newDNSNames, alreadyExistsDNSNames := poller.addRule(uuid, sourceRuleCopy)
		// only debug print for new names, since this function is called
		// unconditionally, even when we insert generated rules (which aren't new)
		if len(newDNSNames) > 0 {
			log.WithFields(logrus.Fields{
				"newDNSNames":           newDNSNames,
				"alreadyExistsDNSNames": alreadyExistsDNSNames,
				"numRules":              len(sourceRules),
			}).Debug("Added FQDN to poll list")
		}
	}
}

// StopPollForDNSName runs the bookkeeping to remove each api.Rule from
// corresponding dnsName entries in sourceRules and IPs.  When no more rules
// rely on a specific dnsName, we remove it from the maps and stop polling for
// it. It expects rules to still be labelled with a ToFQDN-UUID if
// StartPollForDNSName had added the label on insertion.
// Note: rule deletion in policy.Repository is by label, where the rules must
// have at least the labels in the delete.  This means our ToFQDN-UUID label,
// and later ToCIDRSet additions will also be deleted correctly, and no action
// is needed here.
func (poller *DNSPoller) StopPollForDNSName(sourceRules []*api.Rule) {
	poller.Lock()
	defer poller.Unlock()

	for _, sourceRule := range sourceRules {
		// skip unmarked rules, nothing to do
		if !sourceRule.Labels.Has(uuidLabelSearchKey) {
			continue
		}

		uuid := getRuleUUIDLabel(sourceRule)
		noLongerPolledDNSNames := poller.removeRule(uuid, sourceRule)
		log.WithFields(logrus.Fields{
			"noLongerPolled": noLongerPolledDNSNames,
		}).Debug("Removed FQDN from poll list")
	}
}

// LookupUpdateDNS runs a DNS lookup for each stored DNS name, storing updates,
// and then emits regenerated policy rules.
// The general steps are:
// 1- take a snapshot of DNS names to lookup from poller, into dnsNamesToPoll
// 2- Do a DNS lookup for each DNS name (map key) in poller via LookupDNSNames
// 3- Update IPs for each dnsName in poller. If the IPs have changed for the
// name, store which rules must be updated in rulesToUpdate. This is a set and
// is deduped
// 4- For each rule in rulesToUpdate, generate a new policy rule with IPs
// 5- If we have any rules to update, emit them with AddGeneratedRules
func (poller *DNSPoller) LookupUpdateDNS() error {
	// Collect the DNS names that need lookups. This avoids locking
	// poller during lookups.
	dnsNamesToPoll := poller.GetDNSNames()

	// lookup the DNS names. Names with failures will not be updated (and we
	// will use the most recent data below)
	lookupTime := time.Now()
	updatedDNSIPs, errorDNSNames := poller.config.LookupDNSNames(dnsNamesToPoll)
	for dnsName, err := range errorDNSNames {
		log.WithError(err).WithField("matchName", dnsName).
			Warn("Cannot resolve FQDN. Traffic egressing to this destination may be incorrectly dropped due to stale data.")
	}

	// TODO: when poller can get the TTLs of DNS responses, pass that here
	return poller.UpdateGenerateDNS(lookupTime, updatedDNSIPs)
}

// UpdateGenerateDNS inserts the new DNS information into the cache, and
// regenerates rules that need to be regenerated.
func (poller *DNSPoller) UpdateGenerateDNS(lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) error {
	// Update IPs in poller
	uuidsToUpdate, updatedDNSNames := poller.UpdateDNSIPs(lookupTime, updatedDNSIPs)
	for dnsName, IPs := range updatedDNSNames {
		log.WithFields(logrus.Fields{
			"matchName":     dnsName,
			"IPs":           IPs,
			"uuidsToUpdate": uuidsToUpdate,
		}).Debug("Updated FQDN with new IPs")
	}

	// Generate a new rule for each sourceRule that needs an update.
	rulesToUpdate, notFoundUUIDs := poller.GetRulesByUUID(uuidsToUpdate)
	if len(notFoundUUIDs) != 0 {
		log.WithField("uuid", strings.Join(notFoundUUIDs, ",")).
			Debug("Did not find all rules during update")
	}
	generatedRules, namesMissingIPs := poller.GenerateRulesFromSources(rulesToUpdate)
	if len(namesMissingIPs) != 0 {
		log.WithField(logfields.DNSName, strings.Join(namesMissingIPs, ",")).
			Warn("Missing IPs for ToFQDN rule")
	}

	// no rules to add, do not call AddGeneratedRules below
	if len(generatedRules) == 0 {
		return nil
	}

	// emit the new rules
	return poller.config.AddGeneratedRules(generatedRules)
}

// GetDNSNames returns a snapshot of the DNS names in DNSPoller
func (poller *DNSPoller) GetDNSNames() (dnsNames []string) {
	poller.Lock()
	defer poller.Unlock()

	for name := range poller.IPs {
		dnsNames = append(dnsNames, name)
	}

	return dnsNames
}

// UpdateDNSIPs updates the IPs for each DNS name in updatedDNSIPs.
// It returns:
// affectedRules: a list of rule UUIDs that were affected by the new IPs (lookup in .allRules)
// updatedNames: a map of DNS names to the IPs they were updated with.
func (poller *DNSPoller) UpdateDNSIPs(lookupTime time.Time, updatedDNSIPs map[string]*DNSIPRecords) (affectedRules []string, updatedNames map[string][]net.IP) {
	updatedNames = make(map[string][]net.IP, len(updatedDNSIPs))
	affectedRulesSet := make(map[string]struct{}, len(updatedDNSIPs))

	poller.Lock()
	defer poller.Unlock()

perDNSName:
	for dnsName, lookupIPs := range updatedDNSIPs {
		updated := poller.updateIPsForName(lookupTime, dnsName, lookupIPs.IPs, lookupIPs.TTL)

		// The IPs didn't change. No more to be done for this dnsName
		if !updated {
			continue perDNSName
		}

		// record the IPs that were different
		updatedNames[dnsName] = lookupIPs.IPs

		// accumulate the rules affected by new IPs, that we need to update with
		// CIDR rules
		for uuid := range poller.sourceRules[dnsName] {
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
// in the poller and not deleted)
// notFoundUUIDs is the set of UUIDs not found. This can occur when a delete
// races with other operations. It is benign in the sense that if a rule UUID is
// not found, no action is supposed to be taken on it by the poller.
func (poller *DNSPoller) GetRulesByUUID(uuids []string) (sourceRules []*api.Rule, notFoundUUIDs []string) {
	poller.Lock()
	defer poller.Unlock()

	for _, uuid := range uuids {
		rule, ok := poller.allRules[uuid]
		// This may happen if a rule was deleted during the DNS lookups
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
// Note: GenerateRulesFromSources will make a copy each sourceRule
func (poller *DNSPoller) GenerateRulesFromSources(sourceRules []*api.Rule) (generatedRules []*api.Rule, namesMissingIPs []string) {
	poller.Lock()
	defer poller.Unlock()

	var namesMissingMap = make(map[string]struct{})

	for _, sourceRule := range sourceRules {
		newRule := sourceRule.DeepCopy()
		namesMissingIPs := injectToCIDRSetRules(newRule, poller.IPs)
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

// addRule places an api.Rule in the source list for a DNS name.
// uuid must be the unique identifier generated for the ToFQDN-UUID label.
// newDNSNames and oldDNSNames indicate names that were newly added from this
// rule, or that were seen in this rule but were already polled for.
// If newDNSNames and oldDNSNames are both empty, the rule was not added to the
// poll list.
func (poller *DNSPoller) addRule(uuid string, sourceRule *api.Rule) (newDNSNames, oldDNSNames []string) {
	// if we are updating a rule, track which old dnsNames are removed. We store
	// possible names to stop polling for in namesToStopPolling. As we add names
	// from the new rule below, these are cleared.
	namesToStopPolling := make(map[string]struct{})
	if oldRule, exists := poller.allRules[uuid]; exists {
		for _, egressRule := range oldRule.Egress {
			for _, ToFQDN := range egressRule.ToFQDNs {
				matchName := dns.Fqdn(ToFQDN.MatchName)
				namesToStopPolling[matchName] = struct{}{}
			}
		}
	}

	// Always add to allRules
	poller.allRules[uuid] = sourceRule

	// Add a dnsname -> rule reference
	for _, egressRule := range sourceRule.Egress {
		for _, ToFQDN := range egressRule.ToFQDNs {
			dnsName := dns.Fqdn(ToFQDN.MatchName)

			delete(namesToStopPolling, dnsName)

			dnsNameAlreadyExists := poller.ensureExists(dnsName)
			if dnsNameAlreadyExists {
				oldDNSNames = append(oldDNSNames, dnsName)
			} else {
				newDNSNames = append(newDNSNames, dnsName)
				// Add this egress rule as a dependent on dnsName.
				poller.sourceRules[dnsName][uuid] = struct{}{}
			}
		}
	}

	// Stop polling names that were not re-added by deleting them from the IP map
	// Remove references to the uuid that were present in the old rule but not
	// re-added by the new one. This may result in removing the dnsName from
	// polling, if no other rules depend on this dnsName
	for dnsName := range namesToStopPolling {
		if shouldStopPolling := poller.removeFromDNSName(dnsName, uuid); shouldStopPolling {
			delete(poller.IPs, dnsName)
		}
	}

	return newDNSNames, oldDNSNames
}

// removeRule removes an api.Rule from the source rule set for each DNS name,
// and from the IPs if no rules depend on that DNS name. This also stops polling for that DNS name.
// uuid must be a unique identifier for the sourceRule
// noLongerPolled indicates that no more rules rely on this DNS target
func (poller *DNSPoller) removeRule(uuid string, sourceRule *api.Rule) (noLongerPolled []string) {
	// Always delete from allRules
	delete(poller.allRules, uuid)

	// Delete dnsname -> rule references
	for _, egressRule := range sourceRule.Egress {
		for _, ToFQDN := range egressRule.ToFQDNs {
			dnsName := dns.Fqdn(ToFQDN.MatchName)

			if shouldStopPolling := poller.removeFromDNSName(dnsName, uuid); shouldStopPolling {
				delete(poller.IPs, dnsName) // also delete from the IP map, stopping polling
				noLongerPolled = append(noLongerPolled, dnsName)
			}
		}
	}

	return noLongerPolled
}

// removeFromDNSName removes the uuid from the list attached to a dns name. It
// will clean up poller.sourceRules if needed.
// shouldStopPolling indicates that no more rules rely on this DNS target
// Note: This does not touch the IP list, and does not change polling
func (poller *DNSPoller) removeFromDNSName(dnsName, uuid string) (shouldStopPolling bool) {
	// remove the rule from the set of rules that rely on dnsName.
	// Note: this isn't removing dnsName from poller.sourceRules, that is just
	// below.
	delete(poller.sourceRules[dnsName], uuid)

	// Check if any rules remain that rely on this dnsName by checking
	// if the inner map[rule uuid]struct{} set is empty. If none do we
	// can delete it so we no longer poll it.
	isEmpty := len(poller.sourceRules[dnsName]) == 0
	if isEmpty {
		shouldStopPolling = true
		delete(poller.sourceRules, dnsName)
	}

	return shouldStopPolling
}

// ensureExists ensures that we have allocated objects for dnsName, and creates
// them if needed.
func (poller *DNSPoller) ensureExists(dnsName string) (exists bool) {
	_, exists = poller.IPs[dnsName]
	if !exists {
		poller.IPs[dnsName] = make([]net.IP, 0)
		poller.sourceRules[dnsName] = make(map[string]struct{})
	}

	return exists
}

// updateIPsName will update the IPs for dnsName. It always retains a copy of
// newIPs.
// updated is true when the new IPs differ from the old IPs
func (poller *DNSPoller) updateIPsForName(lookupTime time.Time, dnsName string, newIPs []net.IP, ttl int) (updated bool) {
	oldIPs := poller.IPs[dnsName]

	if poller.config.MinTTL > ttl {
		ttl = poller.config.MinTTL
	}

	// TODO: when poller can get the TTLs of DNS responses, apply min(ttl, poller.config.MinTTL)
	poller.cache.Update(lookupTime, dnsName, newIPs, ttl)
	sortedNewIPs := poller.cache.Lookup(dnsName) // DNSCache returns IPs sorted

	// store the new IPs, sorted (to help with the updated determination below)
	poller.IPs[dnsName] = sortedNewIPs

	return !sortedIPsAreEqual(sortedNewIPs, oldIPs)
}
