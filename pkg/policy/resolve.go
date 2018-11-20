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

package policy

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/sirupsen/logrus"
)

// Policy is a structure which contains the resolved policy across all layers
// (L3, L4, and L7).
type Policy struct {
	// ID is the node-local identifier of this Policy.
	ID uint16

	// L4Policy contains the computed L4 and L7 policy.
	L4Policy *L4Policy

	// CIDRPolicy contains the L3 (not L4) CIDR-based policy.
	CIDRPolicy *CIDRPolicy

	// IngressPolicyEnabled specifies whether this policy contains any policy
	// at ingress.
	IngressPolicyEnabled bool

	// EgressPolicyEnabled specifies whether this policy contains any policy
	// at egress.
	EgressPolicyEnabled bool

	// PolicyMapState contains the state of this policy as it relates to the
	// datapath. In the future, this will be factored out of this object to
	// decouple the policy as it relates to the datapath vs. its userspace
	// representation.
	PolicyMapState MapState

	// PolicyOwner describes any type which consumes this Policy object.
	PolicyOwner PolicyOwner
}

// PolicyOwner is anything which consumes a Policy.
type PolicyOwner interface {
	LookupRedirectPort(l4 *L4Filter) uint16
}

func getSecurityIdentities(labelsMap cache.IdentityCache, selector *api.EndpointSelector) []identity.NumericIdentity {
	identities := []identity.NumericIdentity{}
	for idx, labels := range labelsMap {
		if selector.Matches(labels) {
			log.WithFields(logrus.Fields{
				logfields.IdentityLabels: labels,
				logfields.L4PolicyID:     idx,
			}).Debug("L4 Policy matches")
			identities = append(identities, idx)
		}
	}

	return identities
}

func (p *Policy) computeDesiredL4PolicyMapEntries(identityCache cache.IdentityCache) {

	if p.L4Policy == nil {
		return
	}

	policyKeys := p.PolicyMapState

	for _, filter := range p.L4Policy.Ingress {
		keysFromFilter := filter.ToKeys(&filter, trafficdirection.Ingress, identityCache)
		for _, keyFromFilter := range keysFromFilter {
			var proxyPort uint16
			// Preserve the already-allocated proxy ports for redirects that
			// already exist.
			if filter.IsRedirect() {
				proxyPort = p.PolicyOwner.LookupRedirectPort(&filter)
				// If the currently allocated proxy port is 0, this is a new
				// redirect, for which no port has been allocated yet. Ignore
				// it for now. This will be configured by
				// e.addNewRedirectsFromMap once the port has been allocated.
				if proxyPort == 0 {
					continue
				}
			}
			policyKeys[keyFromFilter] = MapStateEntry{ProxyPort: proxyPort}
		}
	}

	for _, filter := range p.L4Policy.Egress {
		keysFromFilter := filter.ToKeys(&filter, trafficdirection.Egress, identityCache)
		for _, keyFromFilter := range keysFromFilter {
			var proxyPort uint16
			// Preserve the already-allocated proxy ports for redirects that
			// already exist.
			if filter.IsRedirect() {
				proxyPort = p.PolicyOwner.LookupRedirectPort(&filter)
				// If the currently allocated proxy port is 0, this is a new
				// redirect, for which no port has been allocated yet. Ignore
				// it for now. This will be configured by
				// e.addNewRedirectsFromMap once the port has been allocated.
				if proxyPort == 0 {
					continue
				}
			}
			policyKeys[keyFromFilter] = MapStateEntry{ProxyPort: proxyPort}
		}
	}
	return
}
