// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/policy/api"
)

// MapSelectorsToIPsLocked iterates through a set of FQDNSelectors and evalutes
// whether they match the DNS Names in the cache. If so, the set of IPs which
// the cache maintains as mapping to each DNS Name are mapped to the matching
// FQDNSelector. Returns the mapping of DNSName to set of IPs which back said
// DNS name, the set of FQDNSelectors which do not map to any IPs, and the set
// of FQDNSelectors mapping to a set of IPs.
func (n *NameManager) MapSelectorsToIPsLocked(fqdnSelectors map[api.FQDNSelector]struct{}) (selectorsMissingIPs []api.FQDNSelector, selectorIPMapping map[api.FQDNSelector][]net.IP) {
	var missing []api.FQDNSelector
	selectorIPMapping = make(map[api.FQDNSelector][]net.IP)

	//log.WithField("fqdnSelectors", fqdnSelectors).Debug("mapSelectorsToIPs")

	// Map each FQDNSelector to set of CIDRs
	for ToFQDN := range fqdnSelectors {
		var matchingIPs []netip.Addr

		if len(ToFQDN.MatchName) > 0 {
			dnsName := prepareMatchName(ToFQDN.MatchName)
			matchingIPs = n.cache.LookupUnsorted(dnsName)
		} else if len(ToFQDN.MatchPattern) > 0 {
			patternRE, ok := n.allSelectors[ToFQDN]
			if !ok {
				panic(fmt.Sprintf("BUG: Missing selector: %+v", ToFQDN))
			}

			matchingIPs = n.cache.LookupByRegexp(patternRE)
		}

		// Mark this FQDNSelector as having no IPs corresponding to it.
		// FQDNSelectors are guaranteed to have only their MatchName OR
		// their MatchPattern set (having both set is invalid per
		// sanitization of FQDNSelectors).
		if len(matchingIPs) == 0 {
			missing = append(missing, ToFQDN)
			continue
		}

		ipsSeen := make(map[netip.Addr]any, len(matchingIPs))
		ips := make([]net.IP, 0, len(ipsSeen))
		for _, ip := range matchingIPs {
			if _, seen := ipsSeen[ip]; seen {
				continue
			}
			ipsSeen[ip] = struct{}{}
			// Alas, th API currently requires returning net.IPs.
			ips = append(ips, ip.Unmap().AsSlice())
		}
		selectorIPMapping[ToFQDN] = ips
	}

	return missing, selectorIPMapping
}

// prepareMatchName ensures a ToFQDNs.matchName field is used consistently.
func prepareMatchName(matchName string) string {
	return dns.FQDN(matchName)
}

// KeepUniqueNames removes duplicate names from the given slice while
// maintaining order. The returned slice re-uses the memory of the
// input slice.
func KeepUniqueNames(names []string) []string {
	deleted := 0
	namesLen := len(names)
	// Use naive O(n^2) in-place algorithm for shorter slices,
	// avoiding all memory allocations.  Limit of 48 names has
	// been experimentally derived. For shorter slices N^2 search
	// is upto 5 times faster than using a map. At 48 both
	// implementations are roughly the same speed.  Above 48 the
	// exponential kicks in and the naive loop becomes slower.
	if namesLen < 48 {
	Loop:
		for i := 0; i < namesLen; i++ {
			current := i - deleted
			for j := 0; j < current; j++ {
				if names[i] == names[j] {
					deleted++
					continue Loop
				}
			}
			names[current] = names[i]
		}
	} else {
		// Use map
		entries := make(map[string]struct{}, namesLen)
		for i := 0; i < namesLen; i++ {
			if _, ok := entries[names[i]]; ok {
				deleted++
				continue
			}
			entries[names[i]] = struct{}{}
			names[i-deleted] = names[i]
		}
	}
	// truncate slice to leave off the duplicates
	return names[:namesLen-deleted]
}
