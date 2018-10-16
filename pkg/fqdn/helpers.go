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

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/uuid"
	"github.com/miekg/dns"
)

// getUUIDFromRuleLabels returns the value of the UUID label
func getRuleUUIDLabel(rule *api.Rule) (uuid string) {
	return rule.Labels.Get(uuidLabelSearchKey)
}

// generateUUIDLabel builds a random UUID label that can be used to uniquely identify
// rules augmented with a "toCIDRSet" based on "toFQDNs".
func generateUUIDLabel() (id *labels.Label) {
	return &labels.Label{
		Key:    generatedLabelNameUUID,
		Value:  uuid.NewUUID().String(),
		Source: labels.LabelSourceCiliumGenerated,
	}
}

// injectToCIDRSetRules adds a ToCIDRSets section to the rule with all ToFQDN
// targets resolved to IPs from dnsNames.
// Pre-existing rules in ToCIDRSet are preserved.
// Note: matchNames in rules are made into FQDNs
func injectToCIDRSetRules(rule *api.Rule, dnsNames map[string][]net.IP) (namesMissingIPs []string) {
	missing := make(map[string]struct{}) // a set to dedup missing dnsNames

	// Add CIDR rules
	// we need to edit Egress[*] in-place
	for egressIdx := range rule.Egress {
		egressRule := &rule.Egress[egressIdx]

		// Generate CIDR rules for each FQDN
		for _, ToFQDN := range egressRule.ToFQDNs {
			dnsName := dns.Fqdn(ToFQDN.MatchName)
			IPs, present := dnsNames[dnsName]
			if !present {
				missing[dnsName] = struct{}{}
			}

			egressRule.ToCIDRSet = append(egressRule.ToCIDRSet, ipsToRules(IPs)...)
		}
	}

	for dnsName := range missing {
		namesMissingIPs = append(namesMissingIPs, dnsName)
	}

	return namesMissingIPs
}

// stripeToCIDRSet ensures no ToCIDRSet is nil when ToFQDNs is non-nil
func stripToCIDRSet(rule *api.Rule) {
	for i := range rule.Egress {
		egressRule := &rule.Egress[i]
		if len(egressRule.ToFQDNs) > 0 {
			egressRule.ToCIDRSet = nil
		}
	}
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

// hasToFQDN indicates whether a ToFQDN rule exists in the api.Rule
func hasToFQDN(rule *api.Rule) bool {
	for _, egressRule := range rule.Egress {
		if len(egressRule.ToFQDNs) > 0 {
			return true
		}
	}

	return false
}

// sortedIPsAreEqual compares two lists of sorted IPs. If any differ it returns
// false.
func sortedIPsAreEqual(a, b []net.IP) bool {
	// the IP set is definitely different if the lengths are different
	if len(a) != len(b) {
		return false
	}

	// lengths are equal, so each member in one set must be in the other
	// Note: we sorted fullNewIPs above, and sorted oldIPs when they were
	// inserted in this function, previously.
	// If any IPs at the same index differ, updated = true.
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
