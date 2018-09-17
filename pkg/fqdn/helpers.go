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

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/uuid"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// getUUIDFromRuleLabels returns the value of the UUID label
func getRuleUUIDLabel(rule *api.Rule) (uuid string) {
	return rule.Labels.Get(uuidLabelSearchKey)
}

// generateUUIDLabel builds a random UUID label that can be used to uniquely identify
// rules augmented with a "toCIDRSet" based on "toFQDNs".
func generateUUIDLabel() labels.Label {
	return labels.NewLabel(generatedLabelNameUUID, uuid.NewUUID().String(), labels.LabelSourceCiliumGenerated)
}

// injectToCIDRSetRules adds a ToCIDRSets section to the rule with all ToFQDN
// targets resolved to IPs stored in cache.
// Pre-existing rules in ToCIDRSet are preserved.
// Note: matchNames in rules are made into FQDNs
func injectToCIDRSetRules(rule *api.Rule, cache *DNSCache) (emittedIPs map[string][]net.IP, namesMissingIPs []string) {
	missing := make(map[string]struct{}) // a set to dedup missing dnsNames
	emitted := make(map[string][]net.IP) // name -> IPs we wrote out

	// Add CIDR rules
	// we need to edit Egress[*] in-place
	for egressIdx := range rule.Egress {
		egressRule := &rule.Egress[egressIdx]

		// Generate CIDR rules for each FQDN
	perToFQDN:
		for _, ToFQDN := range egressRule.ToFQDNs {
			dnsName := dns.Fqdn(ToFQDN.MatchName)
			IPs := cache.LookupByRegexp(regexp.MustCompile(dnsName))
			if len(IPs) == 0 {
				missing[dnsName] = struct{}{}
				continue perToFQDN
			}

			for name, ips := range IPs {
				log.WithFields(logrus.Fields{
					"DNSName": name,
					"IPs":     ips,
					"rule":    ToFQDN.MatchName,
				}).Debug("Emitting matching DNS Name -> IPs for ToFQDNs Rule")
				emitted[ToFQDN.MatchName] = append(emitted[ToFQDN.MatchName], ips...)
				egressRule.ToCIDRSet = append(egressRule.ToCIDRSet, ipsToRules(ips)...)
			}
		}
	}

	for dnsName := range missing {
		namesMissingIPs = append(namesMissingIPs, dnsName)
	}

	return emitted, namesMissingIPs
}

// stripToCIDRSet ensures no ToCIDRSet is nil when ToFQDNs is non-nil
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

// simpleFQDNCheck matches plain DNS names
// See https://en.wikipedia.org/wiki/Hostname
var simpleFQDNCheck = regexp.MustCompile("^[-a-zA-Z0-9.]*[.]$")

// isSimpleFQDN checks if re has only letters and dots
func isSimpleFQDN(re string) bool {
	return simpleFQDNCheck.MatchString(re)
}
