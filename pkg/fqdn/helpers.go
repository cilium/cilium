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
	"strings"

	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/miekg/dns"
)

// mapSelectorsToIPs iterates through a set of FQDNSelectors and evalutes whether
// they match the DNS Names in the cache. If so, the set of IPs which the cache
// maintains as mapping to each DNS Name are mapped to the matching FQDNSelector.
// Returns the mapping of DNSName to set of IPs which back said DNS name, the
// set of FQDNSelectors which do not map to any IPs, and the set of
// FQDNSelectors mapping to a set of IPs.
func mapSelectorsToIPs(fqdnSelectors map[api.FQDNSelectorString]api.FQDNSelector, cache *DNSCache) (selectorsMissingIPs []api.FQDNSelectorString, selectorIPMapping map[api.FQDNSelectorString][]net.IP) {
	missing := make(map[api.FQDNSelectorString]struct{}) // a set to dedup missing dnsNames
	selectorIPMapping = make(map[api.FQDNSelectorString][]net.IP)

	log.WithField("fqdnSelectors", fqdnSelectors).Debug("mapSelectorsToIPs")

	// Map each FQDNSelector to set of CIDRs
	for key, ToFQDN := range fqdnSelectors {
		ips := cache.LookupBySelector(ToFQDN)
		if len(ips) == 0 {
			missing[key] = struct{}{}
		} else {
			selectorIPMapping[key] = ips
		}
	}

	for key := range missing {
		selectorsMissingIPs = append(selectorsMissingIPs, key)
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
