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

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/uuid"
	"github.com/sirupsen/logrus"
)

const (
	generatedLabelSource = "cilium-generated"
	generatedLabelUUID   = "ToFQDN-UUID"
)

var (
	namesToPoll = NewPollMap()
)

type pollMap struct {
	lock.Mutex // this guards both the map and the contents

	targets map[string]*dnsPollTarget
}

func NewPollMap() *pollMap {
	return &pollMap{
		targets: make(map[string]*dnsPollTarget),
	}
}

func (m *pollMap) loadOrStore(dnsName string) (target *dnsPollTarget, dnsNameIsNew bool) {
	target, alreadyExists := m.targets[dnsName]
	if !alreadyExists {
		target = &dnsPollTarget{
			dnsName:     dnsName,
			IPs:         make(map[string]bool),
			sourceRules: make(map[string]*api.Rule),
		}
		m.targets[dnsName] = target
	}

	return target, !alreadyExists
}

func (m *pollMap) Range(f func(name string, target *dnsPollTarget) bool) {
	m.Lock()
	defer m.Unlock()

	for name, target := range m.targets {
		if !f(name, target) {
			return
		}
	}
}

// AddRule places an api.Rule in the source list. `replaced` indicates whether
// the rule already existed in this set.
func (m *pollMap) AddRule(sourceRule *api.Rule) (newDNSNames, oldDNSNames []string) {
	m.Lock()
	defer m.Unlock()

	for _, egressRule := range sourceRule.Egress {
		for _, ToFQDN := range egressRule.ToFQDN {
			for _, dnsName := range ToFQDN.FQDN {
				target, dnsNameAlreadyExists := m.loadOrStore(dnsName)
				target.addRule(sourceRule)
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

// removeRule removes an api.Rule fomr the source rule set. isEmpty indicates
// no more rules rely on this DNS target
func (m *pollMap) RemoveRule(sourceRule *api.Rule) (noLongerPolled []string) {
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

				isEmpty := target.removeRule(sourceRule)
				if isEmpty {
					noLongerPolled = append(noLongerPolled, dnsName)
					delete(m.targets, dnsName)
				}
			}
		}
	}

	return noLongerPolled
}

// getUUIDFromRuleLabels returns the value of the UUID label
func getUUIDFromRuleLabels(rule *api.Rule) (key string) {
	return rule.Labels.Get(generatedLabelSource + ":" + generatedLabelUUID)
}

// generatRuleIDLabel builds a UUID label to unique a rule on PolicyAdd
func generatRuleIDLabel() (id *labels.Label) {
	uuid := uuid.NewUUID().String()
	return &labels.Label{
		Key:    generatedLabelUUID,
		Value:  uuid,
		Source: generatedLabelSource,
	}
}

// generateRuleFromSource creates a new api.Rule with all ToFQDN targets
// resolved to IPs. The IPs are in generated CIDRSet rules in the ToCIDRSet
// section. Pre-existing rules in ToCIDRSet are preserved
// Note: generateRuleFromSource may edit sourceRule in place, or make a copy.
func generateRuleFromSource(sourceRule *api.Rule, updatedDNSNames map[string][]net.IP) (outputRule *api.Rule, err error) {
	outputRule = sourceRule.DeepCopy()

	// Add CIDR rules
	// we need to edit Egress[*] in-place
	for egressIdx := range outputRule.Egress {
		egressRule := &outputRule.Egress[egressIdx]

		// Generate CIDR rules for each FQDN
		for _, ToFQDN := range egressRule.ToFQDN {
			for _, dnsName := range ToFQDN.FQDN {
				IPs, present := updatedDNSNames[dnsName]
				if !present {
					return nil, fmt.Errorf("Cannot look up IPs for FQDN %v", dnsName)
				}

				egressRule.ToCIDRSet = append(egressRule.ToCIDRSet, ipsToRules(IPs)...)
			}
		}
	}

	return outputRule, nil
}

// ipsToRules generates CIDRRules for the IPs passed in.
func ipsToRules(ips []net.IP) (cidrRules []api.CIDRRule) {
	for _, ip := range ips {
		rule := api.CIDRRule{ExceptCIDRs: make([]api.CIDR, 0)}

		if ip.To4() != nil {
			rule.Cidr = api.CIDR(ip.String() + "/32")
		} else {
			rule.Cidr = api.CIDR(ip.String() + "/128")
		}

		cidrRules = append(cidrRules, rule)
	}

	return cidrRules
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
func (target *dnsPollTarget) updateIPs() (lookupIPs []net.IP, affectedRules []*api.Rule, err error) {
	lookupIPs, err = net.LookupIP(target.dnsName)
	if err != nil {
		return nil, nil, fmt.Errorf("Cannot resolve FQDN: %s", err)
	}

	oldIPs := target.IPs

	// update our copy of the IPs and genearate a return set
	// keep a separate copy than what we return to be safe
	target.IPs = make(map[string]bool, len(lookupIPs))
	for _, ip := range lookupIPs {
		normalizedIP := ip.To16().String()
		target.IPs[normalizedIP] = true
	}

	for _, rule := range target.sourceRules {
		affectedRules = append(affectedRules, rule)
	}

	// the IPs are definitely different if the number is different
	if len(lookupIPs) != len(oldIPs) {
		return lookupIPs, affectedRules, nil
	}

	// length is equal, so each member in one set must be in the other
	for _, ip := range lookupIPs {
		normalizedIP := ip.To16().String()
		if _, present := oldIPs[normalizedIP]; !present {
			return lookupIPs, affectedRules, nil
		}
	}

	// the new and previous IPs are the same, no affected rules
	return lookupIPs, nil, nil
}

// addRule places an api.Rule in the source list. `replaced` indicates whether
// the rule already existed in this set.
func (target *dnsPollTarget) addRule(sourceRule *api.Rule) (replaced bool) {
	key := getUUIDFromRuleLabels(sourceRule)
	_, replaced = target.sourceRules[key]
	target.sourceRules[key] = sourceRule

	return replaced
}

// removeRule removes an api.Rule fomr the source rule set. isEmpty indicates
// no more rules rely on this DNS target
func (target *dnsPollTarget) removeRule(sourceRule *api.Rule) (isEmpty bool) {
	key := getUUIDFromRuleLabels(sourceRule)
	delete(target.sourceRules, key)
	return len(target.sourceRules) == 0
}

// StartPollForDNSName sets up the polling for ToFQDN rules in each api.Rule.
// The input rules are tagged with a UUID to allow updating them with IPs for
// each FQDN.
func StartPollForDNSName(sourceRules []*api.Rule) (editedRules []*api.Rule, err error) {
	for _, sourceRule := range sourceRules {
		// This rule has already been seen, and has a UUID. Skip it.  Note: this
		// label can only come from us. An external rule add or replace would
		// remove the UUID-tagged rule (handled in StopPollForDNSName) and we would
		// a new UUID label in this function.
		if sourceRule.Labels.Has(generatedLabelSource + ":" + generatedLabelUUID) {
			continue
		}
		// add a unique ID that we can use later to replace this rule.
		sourceRule.Labels = append(sourceRule.Labels, generatRuleIDLabel())

		newDNSNames, alreadyExistsDNSNames := namesToPoll.AddRule(sourceRule)
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
func StopPollForDNSName(sourceRules []*api.Rule) {
	for _, sourceRule := range sourceRules {
		// skip untagged rules, nothing to do
		if !sourceRule.Labels.Has(generatedLabelSource + ":" + generatedLabelUUID) {
			continue
		}

		noLongerPolledDNSNames := namesToPoll.RemoveRule(sourceRule)
		log.WithFields(logrus.Fields{
			"noLongerPolled": noLongerPolledDNSNames,
		}).Debug("Removed FQDN from poll list")
	}
}

// StartDNSPoller spawns the DNS polling controller. The controller will,
// periodically, run a DNS lookup for each ToFQDN target DNS name then update
// all api.Rules in the agent policy repository with the new IPs. While it only
// updates rule with IP changes, it relies on the internal policy logic to
// return early if the policy is not actually different (e.g. a more broad rule
// applies to an endpoint)
func (d *Daemon) StartDNSPoller() {
	log.Debug("Starting DNS poller for ToFQDN rules")
	controller.NewManager().UpdateController("dns-poller", controller.ControllerParams{
		RunInterval: 5 * time.Second,
		StopFunc: func() error {
			log.Debug("Stopping DNS poller for ToFQDN rules")
			return nil
		},
		DoFunc: func() error {
			var (
				updatedDNSNames = make(map[string][]net.IP)
				rulesToUpdate   = make(map[*api.Rule]bool)
				generatedRules  = make([]*api.Rule, 0)
			)

			// Lookup each dnsName. If it has changed, add the sourceRules to
			// rulesToUpdate and keep a copy of the IPs in updatedDNSNames
			namesToPoll.Range(func(dnsName string, target *dnsPollTarget) bool {
				scopedLog := log.WithField("fqdn", dnsName)

				newIPs, affectedRules, err := target.updateIPs()
				if err != nil {
					scopedLog.WithError(err).Warn("Cannot resolve FQDN")
					return true // continue to the next target
				}
				scopedLog = scopedLog.WithField("ips", newIPs)

				// The IPs didn't change. No more to be done for this dnsName
				if len(affectedRules) == 0 {
					return true
				}

				// accumulate rules we need to update with CIDR rules
				scopedLog.Debug("Updating FQDN IPs")
				updatedDNSNames[dnsName] = newIPs
				for _, rule := range affectedRules {
					rulesToUpdate[rule] = true
				}

				return true
			})

			// Generate a new rule for each sourceRule that needs an update.
			// Note: the labels on the new rule must be consistent with the previous
			// run, so they can be replaced in-place
			for sourceRule := range rulesToUpdate {
				// we will insert this copy to the policy repository
				newRule, err := generateRuleFromSource(sourceRule, updatedDNSNames)
				if err != nil {
					// TODO: make this more specific
					log.WithError(err).Warn("Error generating output rule for ToFQDN rule")
				}

				generatedRules = append(generatedRules, newRule)
			}

			if len(generatedRules) == 0 {
				return nil
			}

			_, err := d.PolicyAdd(generatedRules, &AddOptions{Replace: true})
			return err
		},
	})
}
