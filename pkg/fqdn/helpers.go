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
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/uuid"
)

// DefaultLookupDNSNames runs a DNS lookup for every name in dnsNames
// sequentially and synchronously. It will return:
// DNSIPs: a map of DNS names to their IPs (only contains successful lookups)
// DNSErrors: a map of DNS names to lookup errors.
// It is used by DNSPoller when no alternative LookupDNSNames is provided
func DefaultLookupDNSNames(dnsNames []string) (DNSIPs map[string][]net.IP, DNSErrors map[string]error) {
	DNSIPs = make(map[string][]net.IP)
	for _, dnsName := range dnsNames {
		lookupIPs, err := net.LookupIP(dnsName)
		if err != nil {
			DNSErrors[dnsName] = err
			continue
		}
		DNSIPs[dnsName] = lookupIPs
	}

	return DNSIPs, DNSErrors
}

// DefaultAddGeneratedRules logs each rule in generatedRules. It is not
// expected to be used but will be when AddGeneratedRules is nil in DNSPoller
func DefaultAddGeneratedRules(generatedRules []*api.Rule) error {
	for _, rule := range generatedRules {
		log.WithField("rule", rule).Debug("Generate ToFQDN rule sent to DefaultAddGeneratedRules")
	}
	return nil
}

// getUUIDFromRuleLabels returns the value of the UUID label
func getUUIDFromRuleLabels(rule *api.Rule) (uuid string) {
	return rule.Labels.Get(uuidLabelSearchKey)
}

// generateUUIDLabel builds a UUID label to unique a rule on PolicyAdd
func generateUUIDLabel() (id *labels.Label) {
	uuid := uuid.NewUUID().String()
	return &labels.Label{
		Key:    generatedLabelNameUUID,
		Value:  uuid,
		Source: labels.LabelSourceCiliumGenerated,
	}
}

// generateRuleFromSource creates a new api.Rule with all ToFQDN targets
// resolved to IPs. The IPs are in generated CIDRSet rules in the ToCIDRSet
// section. Pre-existing rules in ToCIDRSet are preserved
// Note: generateRuleFromSource will make a copy of sourceRule
func generateRuleFromSource(sourceRule *api.Rule, updatedDNSNames map[string][]net.IP) (outputRule *api.Rule, err error) {
	outputRule = sourceRule.DeepCopy()

	// Add CIDR rules
	// we need to edit Egress[*] in-place
	for egressIdx := range outputRule.Egress {
		egressRule := &outputRule.Egress[egressIdx]

		// Generate CIDR rules for each FQDN
		for _, ToFQDN := range egressRule.ToFQDNs {
			dnsName := ToFQDN.MatchName
			IPs, present := updatedDNSNames[dnsName]
			if !present {
				return nil, fmt.Errorf("Cannot look up IPs for FQDN %s", dnsName)
			}

			egressRule.ToCIDRSet = append(egressRule.ToCIDRSet, ipsToRules(IPs)...)
		}
	}

	return outputRule, nil
}

// ipsToRules generates CIDRRules for the IPs passed in.
func ipsToRules(ips []net.IP) (cidrRules []api.CIDRRule) {
	for _, ip := range ips {
		rule := api.CIDRRule{ExceptCIDRs: make([]api.CIDR, 0)}
		rule.Generated = true
		if ip.To4() != nil {
			rule.Cidr = api.CIDR(ip.String() + "/32")
		} else {
			rule.Cidr = api.CIDR(ip.String() + "/128")
		}

		cidrRules = append(cidrRules, rule)
	}

	return cidrRules
}
