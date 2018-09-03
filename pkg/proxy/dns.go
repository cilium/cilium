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
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
)

var (
	DNSProxyPort    int
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
	log.Info("UpdateRules")

	for _, rule := range dr.currentRules {
		for _, dnsRule := range rule.DNS {
			DefaultDNSProxy.RemoveAllowed(dnsRule.MatchName, dr.redirect.id)
		}
	}
	dr.currentRules = nil

	for _, rule := range dr.redirect.rules {
		for _, dnsRule := range rule.DNS {
			log.Infof("DNS UpdateRules add %v", dnsRule.MatchName)
			DefaultDNSProxy.AddAllowed(dnsRule.MatchName, dr.redirect.id)
		}
	}
	dr.currentRules = copyRules(dr.redirect.rules)

	return nil
}

// Close the redirect.
func (dr *dnsRedirect) Close(wg *completion.WaitGroup) {
	log.Info("Close")

	for _, rule := range dr.currentRules {
		for _, dnsRule := range rule.DNS {
			DefaultDNSProxy.RemoveAllowed(dnsRule.MatchName, dr.redirect.id)
		}
	}
	dr.currentRules = nil
}

// creatednsRedirect creates a redirect to the dns proxy. The redirect structure passed
// in is safe to access for reading and writing.
func createDNSRedirect(r *Redirect, conf dnsConfiguration, endpointInfoRegistry logger.EndpointInfoRegistry) (RedirectImplementation, error) {
	dr := &dnsRedirect{
		redirect:             r,
		conf:                 conf,
		endpointInfoRegistry: endpointInfoRegistry,

		// FIXME: this is bad. The port was given to us in r but it's unclear who
		// will release it, nor if this global port will be released when any DNS
		// rule is removed.
		DNSProxyPort: uint16(DNSProxyPort),
	}
	r.ProxyPort = dr.DNSProxyPort

	log.Infof("DNS createDNSRedirect redir %+v", dr)
	log.Infof("DNS createDNSRedirect r %+v", r)
	log.Infof("DNS createDNSRedirect endpointInfoRegistry %+v", r)

	return dr, dr.UpdateRules(nil)
}

func copyRules(rules policy.L7DataMap) policy.L7DataMap {
	currentRules := policy.L7DataMap{}
	for key, val := range rules {
		currentRules[key] = val
	}
	return currentRules
}
