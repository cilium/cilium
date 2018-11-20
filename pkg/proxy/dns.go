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

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/sirupsen/logrus"
)

var (
	// DNSProxyPort is the user-configured global, shared, DNS listen port used
	// by the DNS Proxy. Both UDP and TCP are handled on the same port. When it
	// is 0 a random port will be assigned, and can be obtained from
	// DefaultDNSProxy below.
	DNSProxyPort int

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

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (dr *dnsRedirect) UpdateRules(wg *completion.WaitGroup) error {
	var toRemove, toAdd []string

	for _, rule := range dr.currentRules {
		for _, dnsRule := range rule.DNS {
			toRemove = append(toRemove, dnsRule.MatchName)
		}
	}

	for _, rule := range dr.redirect.rules {
		for _, dnsRule := range rule.DNS {
			toAdd = append(toAdd, dnsRule.MatchName)
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

// Close the redirect.
func (dr *dnsRedirect) Close(wg *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc) {
	for _, rule := range dr.currentRules {
		for _, dnsRule := range rule.DNS {
			DefaultDNSProxy.RemoveAllowed(dnsRule.MatchName, fmt.Sprintf("%d", dr.redirect.endpointID))
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
	r.ProxyPort = dr.DNSProxyPort

	log.WithFields(logrus.Fields{
		"dnsRedirect": dr,
		"conf":        conf,
	}).Debug("Creating DNS Proxy redirect")

	return dr, dr.UpdateRules(nil)
}

func copyRules(rules policy.L7DataMap) policy.L7DataMap {
	currentRules := policy.L7DataMap{}
	for key, val := range rules {
		currentRules[key] = val
	}
	return currentRules
}
