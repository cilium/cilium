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
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
)

// dnsRedirect implements the Redirect interface for an l7 proxy
type dnsRedirect struct {
	redirect             *Redirect
	endpointInfoRegistry logger.EndpointInfoRegistry
	conf                 dnsConfiguration
	rules                policy.L7DataMap
}

type dnsConfiguration struct {
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (k *dnsRedirect) UpdateRules(wg *completion.WaitGroup) error {
	log.Info("UpdateRules")
	return nil
}

// Close the redirect.
func (k *dnsRedirect) Close(wg *completion.WaitGroup) {
	log.Info("Close")
}

// creatednsRedirect creates a redirect to the dns proxy. The redirect structure passed
// in is safe to access for reading and writing.
func createDNSRedirect(r *Redirect, conf dnsConfiguration, endpointInfoRegistry logger.EndpointInfoRegistry) (RedirectImplementation, error) {
	redir := &dnsRedirect{
		redirect:             r,
		conf:                 conf,
		endpointInfoRegistry: endpointInfoRegistry,
	}
	log.Infof("createDNSRedirect %v", redir)

	return redir, nil
}
