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
	rules                policy.L7DataMap
	DNSProxyPort         uint16
}

type dnsConfiguration struct {
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (r *dnsRedirect) UpdateRules(wg *completion.WaitGroup) error {
	log.Info("UpdateRules")

	for _, rule := range r.rules {
		for _, dnsRule := range rule.DNS {
			DefaultDNSProxy.AddAllowed(dnsRule.MatchName, fmt.Sprintf("%p", r.redirect))
		}
	}

	return nil
}

// Close the redirect.
func (r *dnsRedirect) Close(wg *completion.WaitGroup) {
	log.Info("Close")

	for _, rule := range r.rules {
		for _, dnsRule := range rule.DNS {
			DefaultDNSProxy.RemoveAllowed(dnsRule.MatchName, fmt.Sprintf("%p", r.redirect))
		}
	}
}

// creatednsRedirect creates a redirect to the dns proxy. The redirect structure passed
// in is safe to access for reading and writing.
func createDNSRedirect(r *Redirect, conf dnsConfiguration, endpointInfoRegistry logger.EndpointInfoRegistry) (RedirectImplementation, error) {
	redir := &dnsRedirect{
		redirect:             r,
		conf:                 conf,
		endpointInfoRegistry: endpointInfoRegistry,

		// FIXME: this is bad. The port was given to us in r but it's unclear who
		// will release it, and if this global port will be released when any DNS
		// rules is removed.
		DNSProxyPort: uint16(DNSProxyPort),
	}
	r.ProxyPort = redir.DNSProxyPort

	log.Infof("DNS createDNSRedirect redir %+v", redir)
	log.Infof("DNS createDNSRedirect r %+v", r)
	log.Infof("DNS createDNSRedirect endpointInfoRegistry %+v", r)

	for _, rule := range r.rules {
		for _, dnsRule := range rule.DNS {
			DefaultDNSProxy.AddAllowed(dnsRule.MatchName, fmt.Sprintf("%p", redir))
		}
	}

	return redir, nil
}
