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

package proxy

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var (
	// DefaultDNSProxy is the global, shared, DNS Proxy singleton.
	DefaultDNSProxy *dnsproxy.DNSProxy
)

// dnsRedirect implements the Redirect interface for an l7 proxy
type dnsRedirect struct {
	redirect *Redirect
	rules    policy.L7DataMap
}

// setRules replaces old l7 rules of a redirect with new ones.
func (dr *dnsRedirect) setRules(newRules policy.L7DataMap) {
	var toRemove, toAdd []string

	for _, rule := range dr.rules {
		for _, dnsRule := range rule.DNS {
			if len(dnsRule.MatchName) > 0 {
				dnsName := strings.ToLower(dns.Fqdn(dnsRule.MatchName))
				dnsNameAsRE := matchpattern.ToRegexp(dnsName)
				toRemove = append(toRemove, dnsNameAsRE)
			}
			if len(dnsRule.MatchPattern) > 0 {
				dnsPattern := matchpattern.Sanitize(dnsRule.MatchPattern)
				dnsPatternAsRE := matchpattern.ToRegexp(dnsPattern)
				toRemove = append(toRemove, dnsPatternAsRE)
			}
		}
	}

	for _, rule := range newRules {
		for _, dnsRule := range rule.DNS {
			if len(dnsRule.MatchName) > 0 {
				dnsName := strings.ToLower(dns.Fqdn(dnsRule.MatchName))
				dnsNameAsRE := matchpattern.ToRegexp(dnsName)
				toAdd = append(toAdd, dnsNameAsRE)
			}
			if len(dnsRule.MatchPattern) > 0 {
				dnsPattern := matchpattern.Sanitize(dnsRule.MatchPattern)
				dnsPatternAsRE := matchpattern.ToRegexp(dnsPattern)
				toAdd = append(toAdd, dnsPatternAsRE)
			}
		}
	}

	log.WithFields(logrus.Fields{
		"add":                toAdd,
		"remove":             toRemove,
		logfields.EndpointID: dr.redirect.endpointID,
	}).Debug("DNS Proxy updating matchNames in allowed list during UpdateRules")
	DefaultDNSProxy.UpdateAllowed(toAdd, toRemove, fmt.Sprintf("%d", dr.redirect.endpointID))
	dr.rules = newRules
}

// UpdateRules atomically replaces the proxy rules in effect for this redirect.
// It is not aware of revision number and doesn't account for out-of-order
// calls to UpdateRules or the returned RevertFunc.
// Called with k.redirect locked.
func (dr *dnsRedirect) UpdateRules(rules policy.L7DataMap) revert.RevertFunc {
	oldRules := dr.rules
	dr.setRules(rules)
	return func() error {
		dr.redirect.mutex.Lock()
		dr.setRules(oldRules)
		dr.redirect.mutex.Unlock()
		return nil
	}
}

// Close the redirect.
func (dr *dnsRedirect) Close() (revert.FinalizeFunc, revert.RevertFunc) {
	return func() {
		for _, rule := range dr.rules {
			for _, dnsRule := range rule.DNS {
				dnsName := strings.ToLower(dns.Fqdn(dnsRule.MatchName))
				dnsNameAsRE := matchpattern.ToRegexp(dnsName)
				DefaultDNSProxy.RemoveAllowed(dnsNameAsRE, fmt.Sprintf("%d", dr.redirect.endpointID))

				dnsPattern := matchpattern.Sanitize(dnsRule.MatchPattern)
				dnsPatternAsRE := matchpattern.ToRegexp(dnsPattern)
				DefaultDNSProxy.RemoveAllowed(dnsPatternAsRE, fmt.Sprintf("%d", dr.redirect.endpointID))
			}
		}
		dr.rules = nil
	}, nil
}

// creatednsRedirect creates a redirect to the dns proxy. The redirect structure passed
// in is safe to access for reading and writing.
func createDNSRedirect(r *Redirect) (RedirectImplementation, error) {
	dr := &dnsRedirect{
		redirect: r,
	}

	log.WithFields(logrus.Fields{
		"dnsRedirect": dr,
	}).Debug("Creating DNS Proxy redirect")

	return dr, nil
}
