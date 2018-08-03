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
	"bytes"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
)

// generatedLabelNameUUID is the label key for policy rules that contain a
// ToFQDN section and need to be updated
const generatedLabelNameUUID = "ToFQDN-UUID"

// uuidLabelSearchKey is an *extended* label key. This is because .Has
// expects the source:key delimiter to be the labels.PathDelimiter
var uuidLabelSearchKey = generateUUIDLabel(nil).GetExtendedKey()

// StartDNSPoller spawns a singleton DNS polling controller. The controller
// will, periodically, run a DNS lookup for each ToFQDN target DNS name
// inserted with StartPollForDNSName.
// Note: Repeated calls will replace earlier instances of the controller.
func StartDNSPoller(poller *DNSPoller) {
	log.Debug("Starting DNS poller for ToFQDN rules")
	controller.NewManager().UpdateController("dns-poller", controller.ControllerParams{
		RunInterval: 5 * time.Second,
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
// DNSPollerConfig can be opitonally used to set how the DNS lookups are
// executed (via LookupDNSNames) and how generated policy rules are handled
// (via AddGeneratedRules).
type DNSPoller struct {
	lock.Mutex // this guards both maps and their contents

	// config is a copy from when this instance was initialized.
	// It is read-only once set
	config DNSPollerConfig

	// IPs maps dnsNames as strings to the most recent IPs seen for them. It is,
	// in effect, a reflection of the realized DNS -> IP state (but acts as a
	// source of information for the CIDR rules we generate)
	// Note: The IP slice is sorted. on insert in updateIPsForName, and should
	// not be reshuffled.
	IPs map[string][]net.IP

	// sourceRule maps dnsNames to a map of rule UUID to rules that depend on
	// that dnsName. It is the desired state for DNS -> IP data, and drives IPs
	// above, which drives CIDR rule generation.
	// The data here is map[dnsName][rule uuid]*api.Rule where the inner map acts
	// as a refcount of rules that depend on this dnsName.
	sourceRules map[string]map[string]*api.Rule
}

// DNSPollerConfig is a simple configuration structure to set how DNSPoller
// does DNS lookups and emits generated policy rules via the AddGeneratedRules
// callback.
// When LookupDNSNames is nil, fqdn.DNSLookupDefaultResolver is used.
// When AddGeneratedRules is nil, it is a no-op
type DNSPollerConfig struct {
	LookupDNSNames    func(dnsNames []string) (DNSIPs map[string][]net.IP, errorDNSNames map[string]error)
	AddGeneratedRules func([]*api.Rule) error
}

// NewDNSPoller creates an initialized DNSPoller. It does not start the controller (use .Start)
func NewDNSPoller(config DNSPollerConfig) *DNSPoller {
	if config.LookupDNSNames == nil {
		config.LookupDNSNames = DNSLookupDefaultResolver
	}

	if config.AddGeneratedRules == nil {
		config.AddGeneratedRules = func(generatedRules []*api.Rule) error { return nil }
	}

	return &DNSPoller{
		config:      config,
		IPs:         make(map[string][]net.IP),
		sourceRules: make(map[string]map[string]*api.Rule),
	}
}

// MarkToFQDNRules adds a tracking label to the rule, if it contains ToFQDN
// rules. The label is used to ensure that the ToFQDN rules are replaced
// correctly when they are regenerated with IPs.
// NOTE: It edits the rules in-place
func MarkToFQDNRules(sourceRules []*api.Rule) {
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
		uuidLabel := generateUUIDLabel(sourceRule.Labels)
		sourceRule.Labels = append(sourceRule.Labels, uuidLabel)
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
		// make a copy to avoid breaking the input rules in any way
		sourceRuleCopy := sourceRule.DeepCopy()

		if !sourceRule.Labels.Has(uuidLabelSearchKey) {
			continue perRule
		}

		uuid := getUUIDFromRuleLabels(sourceRule)
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

		uuid := getUUIDFromRuleLabels(sourceRule)
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
	updatedDNSIPs, errorDNSNames := poller.config.LookupDNSNames(dnsNamesToPoll)
	for dnsName, err := range errorDNSNames {
		log.WithError(err).WithField("matchName", dnsName).
			Warn("Cannot resolve FQDN. Traffic egressing to this destination may be incorrectly dropped due to stale data.")
	}

	// Update IPs in poller
	rulesToUpdate, updatedDNSNames := poller.UpdateDNSIPs(updatedDNSIPs)
	for dnsName, IPs := range updatedDNSNames {
		log.WithFields(logrus.Fields{
			"matchName":     dnsName,
			"IPs":           IPs,
			"rulesToUpdate": rulesToUpdate,
		}).Debug("Updated FQDN with new IPs")
	}

	// Generate a new rule for each sourceRule that needs an update.
	rulesToUpdateList := make([]*api.Rule, 0, len(rulesToUpdate))
	for _, rule := range rulesToUpdate {
		rulesToUpdateList = append(rulesToUpdateList, rule)
	}
	generatedRules, namesMissingIPs := poller.GenerateRulesFromSources(rulesToUpdateList)
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
// affectedRules: a set of *api.Rule that were affected by the new IPs (uniqued by UUID as the map key)
// updatedNames: a map of DNS names to the IPs they were updated with. This is always a subset of updatedDNSIPs.
func (poller *DNSPoller) UpdateDNSIPs(updatedDNSIPs map[string][]net.IP) (affectedRules map[string]*api.Rule, updatedNames map[string][]net.IP) {
	updatedNames = make(map[string][]net.IP, len(updatedDNSIPs))
	affectedRules = make(map[string]*api.Rule, len(updatedDNSIPs))
	poller.Lock()
	defer poller.Unlock()

perDNSName:
	for dnsName, lookupIPs := range updatedDNSIPs {
		updated := poller.updateIPsForName(dnsName, lookupIPs)

		// The IPs didn't change. No more to be done for this dnsName
		if !updated {
			continue perDNSName
		}

		// record the IPs that were different
		updatedNames[dnsName] = lookupIPs

		// accumulate the rules affected by new IPs, that we need to update with
		// CIDR rules
		for _, rule := range poller.sourceRules[dnsName] {
			uuid := getUUIDFromRuleLabels(rule)
			affectedRules[uuid] = rule
		}
	}

	return affectedRules, updatedNames
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
		newRule, namesMissingIPs := generateRuleFromSource(sourceRule, poller.IPs)
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
	for _, egressRule := range sourceRule.Egress {
		for _, ToFQDN := range egressRule.ToFQDNs {
			dnsName := ToFQDN.MatchName
			dnsNameAlreadyExists := poller.ensureExists(dnsName)
			if dnsNameAlreadyExists {
				oldDNSNames = append(oldDNSNames, dnsName)
			} else {
				newDNSNames = append(newDNSNames, dnsName)
				// Add this egress rule as a dependent on dnsName.
				poller.sourceRules[dnsName][uuid] = sourceRule
			}
		}
	}

	return newDNSNames, oldDNSNames
}

// removeRule removes an api.Rule from the source rule set for each DNS name,
// and from the IPs if no rules depend on that DNS name. This also stops polling for that DNS name.
// ruleKey must be a unique identifier for the sourceRule
// isEmpty indicates no more rules rely on this DNS target
func (poller *DNSPoller) removeRule(ruleKey string, sourceRule *api.Rule) (noLongerPolled []string) {
	for _, egressRule := range sourceRule.Egress {
		for _, ToFQDN := range egressRule.ToFQDNs {
			dnsName := ToFQDN.MatchName
			_, exists := poller.IPs[dnsName]
			if !exists {
				// no-op if nothing is there
				return
			}

			// remove the rule from the set of rules that rely on dnsName.
			// Note: this isn't removing dnsName from poller.sourceRules, that is just
			// below.
			uuid := getUUIDFromRuleLabels(sourceRule)
			delete(poller.sourceRules[dnsName], uuid)

			// Check if there remain any rules that rely on this dnsName by checking
			// if the inner map[rule uuid]*api.Rule map is empty (it is acting as a
			// set of *api.Rule). If none do we can delete it so we no longer poll
			// it.
			isEmpty := len(poller.sourceRules[dnsName]) == 0
			if isEmpty {
				noLongerPolled = append(noLongerPolled, dnsName)
				delete(poller.sourceRules, dnsName)
				delete(poller.IPs, dnsName) // also delete from the IP map, stopping polling
			}
		}
	}

	return noLongerPolled
}

// ensureExists ensures that we have allocated objects for dnsName, and creates
// them if needed.
func (poller *DNSPoller) ensureExists(dnsName string) (exists bool) {
	_, exists = poller.IPs[dnsName]
	if !exists {
		poller.IPs[dnsName] = make([]net.IP, 0)
		poller.sourceRules[dnsName] = make(map[string]*api.Rule)
	}

	return exists
}

// updateIPsName will update the IPs for dnsName. It always retains a copy of
// newIPs.
// updated is true when the new IPs differ from the old IPs
func (poller *DNSPoller) updateIPsForName(dnsName string, newIPs []net.IP) (updated bool) {
	oldIPs := poller.IPs[dnsName]

	// store the new IPs, sorted (to help with the updated determination below)
	sortedNewIPs := make([]net.IP, len(newIPs)) // copy uses len(dst) not cap!
	copy(sortedNewIPs, newIPs)
	sort.Slice(sortedNewIPs, func(i, j int) bool {
		return bytes.Compare(sortedNewIPs[i], sortedNewIPs[j]) == -1
	})
	poller.IPs[dnsName] = sortedNewIPs

	// the IP set is definitely different if the lengths are different
	if len(poller.IPs[dnsName]) != len(oldIPs) {
		return true
	}

	// lengths are equal, so each member in one set must be in the other
	// Note: we sorted newIPs above, and sorted oldIPs when they were inserted in
	// this function, previously.
	// If any IPs at the same index differ, updated = true.
	for idx := range poller.IPs[dnsName] {
		if !poller.IPs[dnsName][idx].Equal(oldIPs[idx]) {
			return true
		}
	}

	// the new and old IPs are the same, no update
	return false
}
