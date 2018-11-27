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
	"strings"

	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/fqdn/regexpmap"
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
func injectToCIDRSetRules(rule *api.Rule, cache *DNSCache, reMap *regexpmap.RegexpMap) (emittedIPs map[string][]net.IP, namesMissingIPs []string) {
	missing := make(map[string]struct{}) // a set to dedup missing dnsNames
	emitted := make(map[string][]net.IP) // name -> IPs we wrote out

	// Add CIDR rules
	// we need to edit Egress[*] in-place
	for egressIdx := range rule.Egress {
		egressRule := &rule.Egress[egressIdx]

		// Generate CIDR rules for each FQDN
		for _, ToFQDN := range egressRule.ToFQDNs {
			// lookup matching DNS names
			if len(ToFQDN.MatchName) > 0 {
				dnsName := prepareMatchName(ToFQDN.MatchName)
				lookupIPs := cache.Lookup(dnsName)

				// Mark this name missing; it will be unmarked in the loop below
				if len(lookupIPs) == 0 {
					missing[ToFQDN.MatchName] = struct{}{}
				}

				// Accumulate toCIDRSet rules
				log.WithFields(logrus.Fields{
					"DNSName":   dnsName,
					"IPs":       lookupIPs,
					"matchName": ToFQDN.MatchName,
				}).Debug("Emitting matching DNS Name -> IPs for ToFQDNs Rule")
				emitted[dnsName] = append(emitted[dnsName], lookupIPs...)
				egressRule.ToCIDRSet = append(egressRule.ToCIDRSet, api.IPsToCIDRRules(lookupIPs)...)
			}

			if len(ToFQDN.MatchPattern) > 0 {
				// lookup matching DNS names
				dnsPattern := prepareMatchPattern(ToFQDN.MatchPattern)
				patternREStr := matchpattern.ToRegexp(dnsPattern)
				patternRE := reMap.GetPrecompiledRegexp(patternREStr)
				var err error
				if patternRE == nil {
					if patternRE, err = regexp.Compile(patternREStr); err != nil {
						log.WithError(err).Error("Error compiling matchPattern")
					}
				}
				lookupIPs := cache.LookupByRegexp(patternRE)

				// Mark this pattern missing; it will be unmarked in the loop below
				missing[ToFQDN.MatchPattern] = struct{}{}

				// Accumulate toCIDRSet rules
				for name, ips := range lookupIPs {
					log.WithFields(logrus.Fields{
						"DNSName":      name,
						"IPs":          ips,
						"matchPattern": ToFQDN.MatchPattern,
					}).Debug("Emitting matching DNS Name -> IPs for ToFQDNs Rule")
					delete(missing, ToFQDN.MatchPattern)
					emitted[name] = append(emitted[name], ips...)
					egressRule.ToCIDRSet = append(egressRule.ToCIDRSet, api.IPsToCIDRRules(ips)...)
				}
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

// prepareMatchName ensures a ToFQDNs.matchName field is used consistently.
func prepareMatchName(matchName string) string {
	return strings.ToLower(dns.Fqdn(matchName))
}

// prepareMatchPattern ensures a ToFQDNs.matchPattern field is used consistently.
func prepareMatchPattern(matchPattern string) string {
	return strings.ToLower(dns.Fqdn(matchPattern))
}
