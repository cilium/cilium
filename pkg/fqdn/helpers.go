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
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// mapSelectorsToIPs iterates through a set of FQDNSelectors and evalutes whether
// they match the DNS Names in the cache. If so, the set of IPs which the cache
// maintains as mapping to each DNS Name are mapped to the matching FQDNSelector.
// Returns the mapping of DNSName to set of IPs which back said DNS name, the
// set of FQDNSelectors which do not map to any IPs, and the set of
// FQDNSelectors mapping to a set of IPs.
func mapSelectorsToIPs(fqdnSelectors map[api.FQDNSelector]struct{}, cache *DNSCache) (selectorsMissingIPs []api.FQDNSelector, selectorIPMapping map[api.FQDNSelector][]net.IP) {
	missing := make(map[api.FQDNSelector]struct{}) // a set to dedup missing dnsNames
	selectorIPMapping = make(map[api.FQDNSelector][]net.IP)

	log.WithField("fqdnSelectors", fqdnSelectors).Debug("mapSelectorsToIPs")

	// Map each FQDNSelector to set of CIDRs
	for ToFQDN := range fqdnSelectors {
		ipsSelected := make([]net.IP, 0)
		// lookup matching DNS names
		if len(ToFQDN.MatchName) > 0 {
			dnsName := prepareMatchName(ToFQDN.MatchName)
			lookupIPs := cache.Lookup(dnsName)

			// Mark this FQDNSelector as having no IPs corresponding to it.
			// FQDNSelectors are guaranteed to have only their MatchName OR
			// their MatchPattern set (having both set is invalid per
			// sanitization of FQDNSelectors).
			if len(lookupIPs) == 0 {
				missing[ToFQDN] = struct{}{}
			}

			log.WithFields(logrus.Fields{
				"DNSName":   dnsName,
				"IPs":       lookupIPs,
				"matchName": ToFQDN.MatchName,
			}).Debug("Emitting matching DNS Name -> IPs for FQDNSelector")
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

			for name, ips := range lookupIPs {
				log.WithFields(logrus.Fields{
					"DNSName":      name,
					"IPs":          ips,
					"matchPattern": ToFQDN.MatchPattern,
				}).Debug("Emitting matching DNS Name -> IPs for FQDNSelector")
				delete(missing, ToFQDN)
				ipsSelected = append(ipsSelected, ips...)
			}
		}

		ips := ip.KeepUniqueIPs(ipsSelected)
		if len(ips) > 0 {
			selectorIPMapping[ToFQDN] = ips
		}
	}

	for dnsName := range missing {
		selectorsMissingIPs = append(selectorsMissingIPs, dnsName)
	}
	return selectorsMissingIPs, selectorIPMapping
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
