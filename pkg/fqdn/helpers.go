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
	"github.com/cilium/cilium/pkg/ip"
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

// injectToCIDRSetRules resets the ToCIDRSets of all egress rules containing
// ToFQDN matches to the latest IPs in the cache.  Note: matchNames in rules
// are made into FQDNs
func mapSelectorsToIPs(fqdnSelectors map[api.FQDNSelector]struct{}, cache *DNSCache) (emittedIPs map[string][]net.IP, selectorsMissingIPs []api.FQDNSelector, selectorIPMapping map[api.FQDNSelector][]net.IP) {
	missing := make(map[api.FQDNSelector]struct{}) // a set to dedup missing dnsNames
	emitted := make(map[string][]net.IP)           // name -> IPs we wrote out
	selectorIPMapping = make(map[api.FQDNSelector][]net.IP)

	log.WithField("fqdnSelectors", fqdnSelectors).Debug("mapSelectorsToIPs")

	// Build an IP collection to remove all duplicates
	allIPs := []net.IP{}

	// Map each FQDNSelector to set of CIDRs
	for ToFQDN := range fqdnSelectors {
		ipsSelected := make([]net.IP, 0)
		// lookup matching DNS names
		if len(ToFQDN.MatchName) > 0 {
			dnsName := prepareMatchName(ToFQDN.MatchName)
			lookupIPs := cache.Lookup(dnsName)

			// Mark this name missing; it will be unmarked in the loop below
			if len(lookupIPs) == 0 {
				missing[ToFQDN] = struct{}{}
			}

			// Accumulate toCIDRSet rules
			log.WithFields(logrus.Fields{
				"DNSName":   dnsName,
				"IPs":       lookupIPs,
				"matchName": ToFQDN.MatchName,
			}).Debug("Emitting matching DNS Name -> IPs for ToFQDNs Rule")
			emitted[dnsName] = append(emitted[dnsName], lookupIPs...)
			allIPs = append(allIPs, lookupIPs...)
			ipsSelected = append(ipsSelected, lookupIPs...)
		}

		if len(ToFQDN.MatchPattern) > 0 {
			// lookup matching DNS names
			dnsPattern := matchpattern.Sanitize(ToFQDN.MatchPattern)
			patternREStr := matchpattern.ToRegexp(dnsPattern)
			var (
				err       error
				patternRE *regexp.Regexp
			)

			if patternRE, err = regexp.Compile(patternREStr); err != nil {
				log.WithError(err).Error("Error compiling matchPattern")
			}
			lookupIPs := cache.LookupByRegexp(patternRE)

			// Mark this pattern missing; it will be unmarked in the loop below
			missing[ToFQDN] = struct{}{}

			// Accumulate toCIDRSet rules
			for name, ips := range lookupIPs {
				log.WithFields(logrus.Fields{
					"DNSName":      name,
					"IPs":          ips,
					"matchPattern": ToFQDN.MatchPattern,
				}).Debug("Emitting matching DNS Name -> IPs for FQDNSelector")
				delete(missing, ToFQDN)
				emitted[name] = append(emitted[name], ips...)
				allIPs = append(allIPs, ips...)
				ipsSelected = append(ipsSelected, ips...)
			}
		}

		ips := ip.KeepUniqueIPs(ipsSelected)
		selectorIPMapping[ToFQDN] = ips
	}

	for dnsName := range missing {
		selectorsMissingIPs = append(selectorsMissingIPs, dnsName)
	}
	return emitted, selectorsMissingIPs, selectorIPMapping
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

// KeepUniqueNames it gets a array of strings and return a new array of strings
// with the unique names.
func KeepUniqueNames(names []string) []string {
	result := []string{}
	entries := map[string]bool{}

	for _, item := range names {
		if _, ok := entries[item]; ok {
			continue
		}
		entries[item] = true
		result = append(result, item)
	}
	return result
}
