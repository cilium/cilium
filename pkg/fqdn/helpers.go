// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"net"
	"regexp"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/policy/api"
)

// MapSelectorsToIPsLocked iterates through a set of FQDNSelectors and evalutes
// whether they match the DNS Names in the cache. If so, the set of IPs which
// the cache maintains as mapping to each DNS Name are mapped to the matching
// FQDNSelector. Returns the mapping of DNSName to set of IPs which back said
// DNS name, the set of FQDNSelectors which do not map to any IPs, and the set
// of FQDNSelectors mapping to a set of IPs.
func (n *NameManager) MapSelectorsToIPsLocked(fqdnSelectors map[api.FQDNSelector]struct{}) (selectorsMissingIPs []api.FQDNSelector, selectorIPMapping map[api.FQDNSelector][]net.IP) {
	missing := make(map[api.FQDNSelector]struct{}) // a set to dedup missing dnsNames
	selectorIPMapping = make(map[api.FQDNSelector][]net.IP)

	log.WithField("fqdnSelectors", fqdnSelectors).Debug("mapSelectorsToIPs")

	// Map each FQDNSelector to set of CIDRs
	for ToFQDN := range fqdnSelectors {
		ipsSelected := make([]net.IP, 0)
		// lookup matching DNS names
		if len(ToFQDN.MatchName) > 0 {
			dnsName := prepareMatchName(ToFQDN.MatchName)
			lookupIPs := n.cache.Lookup(dnsName)

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
			patternREStr := matchpattern.ToAnchoredRegexp(dnsPattern)
			var (
				err       error
				patternRE *regexp.Regexp
			)

			if patternRE, err = re.CompileRegex(patternREStr); err != nil {
				log.WithError(err).Error("Error compiling matchPattern")
			}
			lookupIPs := n.cache.LookupByRegexp(patternRE)

			// Mark this pattern missing; it will be unmarked in the loop below
			missing[ToFQDN] = struct{}{}

			for name, ips := range lookupIPs {
				if len(ips) > 0 {
					log.WithFields(logrus.Fields{
						"DNSName":      name,
						"IPs":          ips,
						"matchPattern": ToFQDN.MatchPattern,
					}).Debug("Emitting matching DNS Name -> IPs for FQDNSelector")
					delete(missing, ToFQDN)
					ipsSelected = append(ipsSelected, ips...)
				}
			}
		}

		ips := ip.KeepUniqueIPs(ipsSelected)
		if len(ips) > 0 {
			selectorIPMapping[ToFQDN] = ips
		}
	}

	selectorsMissingIPs = make([]api.FQDNSelector, 0, len(missing))
	for dnsName := range missing {
		selectorsMissingIPs = append(selectorsMissingIPs, dnsName)
	}
	return selectorsMissingIPs, selectorIPMapping
}

// prepareMatchName ensures a ToFQDNs.matchName field is used consistently.
func prepareMatchName(matchName string) string {
	return dns.FQDN(matchName)
}
