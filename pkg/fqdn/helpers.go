// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"net/netip"
	"regexp"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/policy/api"
)

// mapSelectorsToNamesLocked iterates through all DNS Names in the cache and
// evaluates if they match the provided fqdnSelector. If so, the matching DNS
// Name with all its associated IPs is collected.
//
// Returns the mapping of DNS names to all IPs selected by that selector.
func (n *NameManager) mapSelectorsToNamesLocked(fqdnSelector api.FQDNSelector) (namesIPMapping map[string][]netip.Addr) {
	namesIPMapping = make(map[string][]netip.Addr)

	// lookup matching DNS names
	if len(fqdnSelector.MatchName) > 0 {
		dnsName := prepareMatchName(fqdnSelector.MatchName)
		lookupIPs := n.cache.Lookup(dnsName)
		if len(lookupIPs) > 0 {
			log.WithFields(logrus.Fields{
				"DNSName":   dnsName,
				"IPs":       lookupIPs,
				"matchName": fqdnSelector.MatchName,
			}).Debug("Emitting matching DNS Name -> IPs for FQDNSelector")
			namesIPMapping[dnsName] = lookupIPs
		}
	}

	if len(fqdnSelector.MatchPattern) > 0 {
		// lookup matching DNS names
		dnsPattern := matchpattern.Sanitize(fqdnSelector.MatchPattern)
		patternREStr := matchpattern.ToAnchoredRegexp(dnsPattern)
		var (
			err       error
			patternRE *regexp.Regexp
		)

		if patternRE, err = re.CompileRegex(patternREStr); err != nil {
			log.WithError(err).Error("Error compiling matchPattern")
			return namesIPMapping
		}
		lookupIPs := n.cache.LookupByRegexp(patternRE)

		for dnsName, ips := range lookupIPs {
			if len(ips) > 0 {
				if log.Logger.IsLevelEnabled(logrus.DebugLevel) {
					log.WithFields(logrus.Fields{
						"DNSName":      dnsName,
						"IPs":          ips,
						"matchPattern": fqdnSelector.MatchPattern,
					}).Debug("Emitting matching DNS Name -> IPs for FQDNSelector")
				}
				namesIPMapping[dnsName] = append(namesIPMapping[dnsName], ips...)
			}
		}
	}

	return namesIPMapping
}

// prepareMatchName ensures a ToFQDNs.matchName field is used consistently.
func prepareMatchName(matchName string) string {
	return dns.FQDN(matchName)
}
