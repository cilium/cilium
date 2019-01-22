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

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/dns"
	"github.com/sirupsen/logrus"
)

var (
	// DefaultDNSProxy is the global, shared, DNS Proxy singleton.
	DefaultDNSProxy *dnsproxy.DNSProxy
)

// dnsRedirect implements the Redirect interface for an l7 proxy
type dnsRedirect struct {
	redirect             *Redirect
	endpointInfoRegistry logger.EndpointInfoRegistry
	conf                 dnsConfiguration
	DNSProxyPort         uint16
	currentRules         policy.L7DataMap
}

type dnsConfiguration struct {
}

// setRules replaces old l7 rules of a redirect with new ones.
func (dr *dnsRedirect) setRules(wg *completion.WaitGroup, newRules policy.L7DataMap) error {
	var toRemove, toAdd []string

	for _, rule := range dr.currentRules {
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

	for _, rule := range dr.redirect.rules {
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
	dr.currentRules = copyRules(dr.redirect.rules)

	return nil
}

// UpdateRules atomically replaces the proxy rules in effect for this redirect.
// It is not aware of revision number and doesn't account for out-of-order
// calls to UpdateRules or the returned RevertFunc.
func (dr *dnsRedirect) UpdateRules(wg *completion.WaitGroup, l4 *policy.L4Filter) (revert.RevertFunc, error) {
	oldRules := dr.currentRules
	err := dr.setRules(wg, dr.redirect.rules)
	revertFunc := func() error {
		return dr.setRules(nil, oldRules)
	}
	return revertFunc, err
}

// Close the redirect.
func (dr *dnsRedirect) Close(wg *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc) {
	for _, rule := range dr.currentRules {
		for _, dnsRule := range rule.DNS {
			dnsName := strings.ToLower(dns.Fqdn(dnsRule.MatchName))
			dnsNameAsRE := matchpattern.ToRegexp(dnsName)
			DefaultDNSProxy.RemoveAllowed(dnsNameAsRE, fmt.Sprintf("%d", dr.redirect.endpointID))

			dnsPattern := matchpattern.Sanitize(dnsRule.MatchPattern)
			dnsPatternAsRE := matchpattern.ToRegexp(dnsPattern)
			DefaultDNSProxy.RemoveAllowed(dnsPatternAsRE, fmt.Sprintf("%d", dr.redirect.endpointID))
		}
	}
	dr.currentRules = nil
	return func() {}, nil
}

// creatednsRedirect creates a redirect to the dns proxy. The redirect structure passed
// in is safe to access for reading and writing.
func createDNSRedirect(r *Redirect, conf dnsConfiguration, endpointInfoRegistry logger.EndpointInfoRegistry) (RedirectImplementation, error) {
	dr := &dnsRedirect{
		redirect:             r,
		conf:                 conf,
		endpointInfoRegistry: endpointInfoRegistry,

		// NOTE: We use a fixed port here but a port was given to us in r. It's
		// unclear who will release it, nor if this global port will be released
		// when any DNS rule is removed. We rely on that happening elsewhere.
		DNSProxyPort: DefaultDNSProxy.BindPort,
	}
	if r.ProxyPort != dr.DNSProxyPort {
		log.WithFields(logrus.Fields{
			"dnsRedirect": dr,
			"conf":        conf,
		}).Errorf("Mismatching DNS proxy port: %d, should be %d", r.ProxyPort, dr.DNSProxyPort)
		r.ProxyPort = dr.DNSProxyPort
	}

	log.WithFields(logrus.Fields{
		"dnsRedirect": dr,
		"conf":        conf,
	}).Debug("Creating DNS Proxy redirect")

	return dr, dr.setRules(nil, r.rules)
}

func copyRules(rules policy.L7DataMap) policy.L7DataMap {
	currentRules := policy.L7DataMap{}
	for key, val := range rules {
		currentRules[key] = val
	}
	return currentRules
}
