// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"net"
	"net/netip"
	"regexp"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/policy/api"
)

// mapSelectorsToIPsLocked iterates through a set of FQDNSelectors and evalutes
// whether they match the DNS Names in the cache. If so, the set of IPs which
// the cache maintains as mapping to each DNS Name are mapped to the matching
// FQDNSelector.
// Returns the mapping of FQDNSelector to all IPs selected by that selector.
func (n *NameManager) mapSelectorsToIPsLocked(fqdnSelectors sets.Set[api.FQDNSelector]) (selectorIPMapping map[api.FQDNSelector][]netip.Addr) {
	selectorIPMapping = make(map[api.FQDNSelector][]netip.Addr)

	log.WithField("fqdnSelectors", fqdnSelectors).Debug("mapSelectorsToIPs")

	// Map each FQDNSelector to set of CIDRs
	for ToFQDN := range fqdnSelectors {
		ipsSelected := make([]net.IP, 0)
		// lookup matching DNS names
		if len(ToFQDN.MatchName) > 0 {
			dnsName := prepareMatchName(ToFQDN.MatchName)
			lookupIPs := n.cache.Lookup(dnsName)

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

			for name, ips := range lookupIPs {
				if len(ips) > 0 {
					log.WithFields(logrus.Fields{
						"DNSName":      name,
						"IPs":          ips,
						"matchPattern": ToFQDN.MatchPattern,
					}).Debug("Emitting matching DNS Name -> IPs for FQDNSelector")
					ipsSelected = append(ipsSelected, ips...)
				}
			}
		}

		ips := ip.KeepUniqueIPs(ipsSelected)
		selectorIPMapping[ToFQDN] = ip.MustAddrsFromIPs(ips)
	}

	return selectorIPMapping
}

// prepareMatchName ensures a ToFQDNs.matchName field is used consistently.
func prepareMatchName(matchName string) string {
	return dns.FQDN(matchName)
}
