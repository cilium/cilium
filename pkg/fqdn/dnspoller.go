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
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
)

// generatedLabelNameUUID is the label key for policy rules that contain a
// ToFQDN section and need to be updated
const generatedLabelNameUUID = "ToFQDN-UUID"

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

	// IPs maps dnsNames as strings to the most recent IPs seen for them
	// Note: The IP slice is sorted. on insert in updateIPsForName, and should
	// not be reshuffled.
	IPs map[string][]net.IP

	// sourceRule maps dnsNames to a map of rule UUID to rules that
	// depend on that dnsName.
	// The map-in-map is used to simplify rule removal.
	sourceRules map[string]map[string]*api.Rule
}

// DNSPollerConfig is a simple configuration structure to set how DNSPoller
// does DNS lookups and emits generated policy rules. Leaving either field
// empty will result in DNSPoller using fqdn.DefaultLookupDNSNames or
// fqdn.DefaultAddGeneratedRules, respectively.
type DNSPollerConfig struct {
	LookupDNSNames    func(dnsNames []string) (DNSIPs map[string][]net.IP, errorDNSNames map[string]error)
	AddGeneratedRules func([]*api.Rule) error
}

// NewDNSPoller creates an initialized DNSPoller. It does not start the controller (use .Start)
func NewDNSPoller(config DNSPollerConfig) *DNSPoller {
	if config.LookupDNSNames == nil {
		config.LookupDNSNames = DefaultLookupDNSNames
	}

	if config.AddGeneratedRules == nil {
		config.AddGeneratedRules = DefaultAddGeneratedRules
	}

	return &DNSPoller{
		config:      config,
		IPs:         make(map[string][]net.IP),
		sourceRules: make(map[string]map[string]*api.Rule),
	}
}

// StartPollForDNSName sets up the polling for ToFQDN rules in each api.Rule
// and returns api.Rules to be inserted into the policy repository. The
// returned rules are tagged with a UUID to allow updating them with IPs for
// each FQDN.
func (poller *DNSPoller) StartPollForDNSName(sourceRules []*api.Rule) (markedRules []*api.Rule, err error) {
	poller.Lock()
	defer poller.Unlock()

perRule:
	for _, sourceRule := range sourceRules {
		// make a copy to avoid breaking the input rules in any way
		sourceRuleCopy := sourceRule.DeepCopy()

		// always add the rule to makedRules, so we don't lose it if we skip below
		markedRules = append(markedRules, sourceRuleCopy)

		// This rule has already been seen, and has a UUID. Do no more processing it.
		// Note: this label can only come from us. An external rule add or replace
		// would lack the UUID-tagged rule and we would add a new UUID label in
		// this function.  Cleanup for existing rules with UUIDs is handled in
		// StopPollForDNSName
		if sourceRule.Labels.Has(uuidLabelSearchKey) {
			continue perRule
		}

		uuidLabel := generateUUIDLabel()
		newDNSNames, alreadyExistsDNSNames := poller.addRule(uuidLabel.Value, sourceRuleCopy)

		// only add a custom label (below) if we processed any ToFQDN rules.
		if (len(newDNSNames) + len(alreadyExistsDNSNames)) > 0 {
			// add a unique ID that we can use later to replace this rule.
			sourceRuleCopy.Labels = append(sourceRuleCopy.Labels, uuidLabel)

			log.WithFields(logrus.Fields{
				"newDNSNames":           newDNSNames,
				"alreadyExistsDNSNames": alreadyExistsDNSNames,
				"numRules":              len(sourceRules),
			}).Debug("Added FQDN to poll list")
		}
	}

	return markedRules, nil
}

// StopPollForDNSName runs the bookkeeping to remove each api.Rule from the
// dnsPollTargets. When a target is empty, it is removed from the DNS names
// that are polled. It expects rules to still be labelled with a ToFQDN-UUID if
// StartPollForDNSName had added it on insertion.
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
		log.WithError(err).WithField("matchName", dnsName).Warn("Cannot resolve FQDN")
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
	var generatedRules []*api.Rule
	for _, sourceRule := range rulesToUpdate {
		newRule, err := generateRuleFromSource(sourceRule, updatedDNSNames)
		if err != nil {
			// TODO: make this more specific
			log.WithError(err).Warn("Error generating policy rule with IPs for ToFQDN rule")
		}

		generatedRules = append(generatedRules, newRule)
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

			// remove the rule from the set of rules for dnsName.
			// Note: this isn't removing dnsName from poller.sourceRules, that is just
			// below.
			uuid := getUUIDFromRuleLabels(sourceRule)
			delete(poller.sourceRules[dnsName], uuid)

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
