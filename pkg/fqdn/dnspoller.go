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
	lock.Mutex // this guards both the map and the contents

	targets map[string]*dnsPollTarget
	config  DNSPollerConfig
	uuid    string // used to unique the controller
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
		targets: make(map[string]*dnsPollTarget),
		config:  config,
	}
}

// StartPollForDNSName sets up the polling for ToFQDN rules in each api.Rule.
// The input rules are tagged with a UUID to allow updating them with IPs for
// each FQDN.
func (poller *DNSPoller) StartPollForDNSName(sourceRules []*api.Rule) (editedRules []*api.Rule, err error) {
	for _, sourceRule := range sourceRules {
		// This rule has already been seen, and has a UUID. Skip it. Note: this
		// label can only come from us. An external rule add or replace would
		// remove the UUID-tagged rule (handled in StopPollForDNSName) and we would
		// a new UUID label in this function.
		if sourceRule.Labels.Has(uuidLabelSearchKey) {
			continue
		}
		uuidLabel := generateUUIDLabel()
		newDNSNames, alreadyExistsDNSNames := poller.addRule(uuidLabel.Value, sourceRule)

		// only add a custom label (below) if we processed any ToFQDN rules,
		// otherwise continue with the other rules
		if (len(newDNSNames) + len(alreadyExistsDNSNames)) == 0 {
			// We assume addRule did not add this to any list, and we don't need the
			// UUID label below.
			continue
		}

		// add a unique ID that we can use later to replace this rule.
		sourceRule.Labels = append(sourceRule.Labels, uuidLabel)

		log.WithFields(logrus.Fields{
			"newDNSNames":           newDNSNames,
			"alreadyExistsDNSNames": alreadyExistsDNSNames,
			"numRules":              len(sourceRules),
		}).Debug("Added FQDN to poll list")

	}

	// the edits are in-place
	return sourceRules, nil
}

// StopPollForDNSName runs the bookkeeping to remove each api.Rule from the
// dnsPollTargets. When a target is empty, it is removed from the DNS names
// that are polled.
// Note: rule deletion in policy.Repository is by label, where at least that
// many labels must match. This means our IP modified rule will be deleted
// correctly, and no action is needed here.
func (poller *DNSPoller) StopPollForDNSName(sourceRules []*api.Rule) {
	for _, sourceRule := range sourceRules {
		// skip untagged rules, nothing to do
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
		log.WithError(err).WithField("fqdn", dnsName).Warn("Cannot resolve FQDN")
	}

	// Update IPs in poller
	rulesToUpdate, updatedDNSNames := poller.UpdateDNSIPs(updatedDNSIPs)
	for dnsName, IPs := range updatedDNSNames {
		log.WithFields(logrus.Fields{
			"fqdn": dnsName,
			"IPs":  IPs,
		}).Debug("Updated FQDN with new IPs")
	}

	// Generate a new rule for each sourceRule that needs an update.
	var generatedRules []*api.Rule
	for sourceRule := range rulesToUpdate {
		newRule, err := generateRuleFromSource(sourceRule, updatedDNSNames)
		if err != nil {
			// TODO: make this more specific
			log.WithError(err).Warn("Error generating policy rule with IPs for ToFQDN rule")
		}

		generatedRules = append(generatedRules, newRule)
	}

	// no rules to add, do not call PolicyAdd below
	if len(generatedRules) == 0 {
		return nil
	}

	// emit the new rules
	return poller.config.AddGeneratedRules(generatedRules)
}

// GetDNSNames returns a snapshot of the DNS names in DNSPoller
func (m *DNSPoller) GetDNSNames() (dnsNames []string) {
	m.Lock()
	defer m.Unlock()

	for name := range m.targets {
		dnsNames = append(dnsNames, name)
	}

	return dnsNames
}

// UpdateDNSIPs updates the IPs for each DNS name in updatedDNSIPs.  It returns
// a set of *api.Rule that were affected by the new IPs(and the names that were
// updated), and a set of DNS Names that were used when updating.
func (m *DNSPoller) UpdateDNSIPs(updatedDNSIPs map[string][]net.IP) (affectedRules map[*api.Rule][]string, updatedNames map[string][]net.IP) {
	updatedNames = make(map[string][]net.IP, len(updatedDNSIPs))
	affectedRules = make(map[*api.Rule][]string, len(updatedDNSIPs))
	m.Lock()
	defer m.Unlock()

	for dnsName, target := range m.targets {
		// Ensure that we have IPs to update for this dnsName. No IPs may happen
		// when a name is added while we do the DNS lookups to populate
		// updatedDNSNames before calling this function
		lookupIPs, found := updatedNames[dnsName]
		if !found || len(lookupIPs) == 0 {
			// We have no data. Do nothing. This will use the most recent data if it
			// was set on target
			continue
		}

		updatedRules := target.updateIPs(lookupIPs)

		// The IPs didn't change. No more to be done for this dnsName
		if len(updatedRules) == 0 {
			continue
		}

		// record which DNS names we used to update rules
		updatedNames[dnsName] = lookupIPs

		// accumulate rules we need to update with CIDR rules
		for _, rule := range updatedRules {
			affectedRules[rule] = append(affectedRules[rule], dnsName)
		}
	}

	return affectedRules, updatedNames
}

// addRule places an api.Rule in the source list.
// ruleKey must be a unique identifier for the sourceRule
// newDNSNames and oldDNSNames indicate names that were newly added from this
// rule, or that were seen in this rule but were already polled for.
// If newDNSNames and oldDNSNames are both empty, the rule was not added to the
// poll list.
func (m *DNSPoller) addRule(ruleKey string, sourceRule *api.Rule) (newDNSNames, oldDNSNames []string) {
	m.Lock()
	defer m.Unlock()

	for _, egressRule := range sourceRule.Egress {
		for _, ToFQDN := range egressRule.ToFQDN {
			for _, dnsName := range ToFQDN.FQDN {
				target, dnsNameAlreadyExists := m.loadOrStore(dnsName)
				target.addRule(ruleKey, sourceRule)

				if dnsNameAlreadyExists {
					oldDNSNames = append(oldDNSNames, dnsName)
				} else {
					newDNSNames = append(newDNSNames, dnsName)
				}
			}
		}
	}

	return newDNSNames, oldDNSNames
}

// removeRule removes an api.Rule fomr the source rule set.
// ruleKey must be a unique identifier for the sourceRule
// isEmpty indicates no more rules rely on this DNS target
func (m *DNSPoller) removeRule(ruleKey string, sourceRule *api.Rule) (noLongerPolled []string) {
	m.Lock()
	defer m.Unlock()

	for _, egressRule := range sourceRule.Egress {
		for _, ToFQDN := range egressRule.ToFQDN {
			for _, dnsName := range ToFQDN.FQDN {

				target, found := m.targets[dnsName]
				if !found {
					// no-op if nothing is there
					return
				}

				isEmpty := target.removeRule(ruleKey, sourceRule)
				if isEmpty {
					noLongerPolled = append(noLongerPolled, dnsName)
					delete(m.targets, dnsName)
				}
			}
		}
	}

	return noLongerPolled
}

// loadOrStore returns the stored object for dnsName, or creates a new one if
// none exists.
func (m *DNSPoller) loadOrStore(dnsName string) (target *dnsPollTarget, loaded bool) {
	target, loaded = m.targets[dnsName]
	if !loaded {
		target = &dnsPollTarget{
			dnsName:     dnsName,
			IPs:         make(map[string]bool),
			sourceRules: make(map[string]*api.Rule),
		}
		m.targets[dnsName] = target
	}

	return target, loaded
}

// dnsPollTarget holds a DNS name that needs to be polled, its most recent
// data, and the api.Rule that depends on it.
type dnsPollTarget struct {
	dnsName     string
	IPs         map[string]bool
	sourceRules map[string]*api.Rule // set of rules that use this DNS name
}

// updateIPs does a DNS lookup, and returns a list of sourceRules that need to
// be regenerated, along with the IPs looked up.
// affectedRules is empty when no rules are returned, meaning the IPs did not
// change
func (target *dnsPollTarget) updateIPs(IPs []net.IP) (affectedRules []*api.Rule) {
	oldIPs := target.IPs

	// update our copy of the IPs
	target.IPs = make(map[string]bool, len(IPs))
	for _, ip := range IPs {
		target.IPs[ip.String()] = true
	}

	// the IPs are definitely different if the lengths are different
	if len(target.IPs) != len(oldIPs) {
		return affectedRules
	}

	// length is equal, so each member in one set must be in the other
	for ip := range target.IPs {
		if _, present := oldIPs[ip]; !present {
			return affectedRules
		}
	}

	for _, rule := range target.sourceRules {
		affectedRules = append(affectedRules, rule)
	}

	// the new and previous IPs are the same, no affected rules
	return nil
}

// addRule places an api.Rule in the source list. `replaced` indicates whether
// the rule already existed in this set.
func (target *dnsPollTarget) addRule(key string, sourceRule *api.Rule) (replaced bool) {
	_, replaced = target.sourceRules[key]
	target.sourceRules[key] = sourceRule

	return replaced
}

// removeRule removes an api.Rule fomr the source rule set. isEmpty indicates
// no more rules rely on this DNS target
func (target *dnsPollTarget) removeRule(key string, sourceRule *api.Rule) (isEmpty bool) {
	delete(target.sourceRules, key)
	return len(target.sourceRules) == 0
}
