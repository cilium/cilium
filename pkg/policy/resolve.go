// Copyright 2018-2019 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"

	"github.com/sirupsen/logrus"
)

// SelectorPolicy is a structure which contains the resolved policy for a
// particular Identity across all layers (L3, L4, and L7), with the policy
// still determined in terms of EndpointSelectors.
type SelectorPolicy struct {
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

	// matchingRules is the set of rules in the repository that were
	// matched during policy resolution. These refer directly into the
	// policy repository and must not be modified.
	//
	// GH-7516 tracks removal of this field.
	matchingRules ruleSlice
}

// EndpointPolicy is a structure which contains the resolved policy across all
// layers (L3, L4, and L7), distilled against a set of identities.
type EndpointPolicy struct {
	*SelectorPolicy

	// PolicyMapState contains the state of this policy as it relates to the
	// datapath. In the future, this will be factored out of this object to
	// decouple the policy as it relates to the datapath vs. its userspace
	// representation.
	// It maps each Key to the proxy port if proxy redirection is needed.
	// Proxy port 0 indicates no proxy redirection.
	// All fields within the Key and the proxy port must be in host byte-order.
	PolicyMapState MapState

	// PolicyOwner describes any type which consumes this EndpointPolicy object.
	PolicyOwner PolicyOwner

	// DeniedIngressIdentities is the set of identities which are not allowed
	// by policy on ingress. This field is populated when an identity does not
	// meet restraints set forth in FromRequires.
	DeniedIngressIdentities cache.IdentityCache

	// DeniedEgressIdentities is the set of identities which are not allowed
	// by policy on egress. This field is populated when an identity does not
	// meet restraints set forth in ToRequires.
	DeniedEgressIdentities cache.IdentityCache
}

// PolicyOwner is anything which consumes a EndpointPolicy.
type PolicyOwner interface {
	LookupRedirectPort(l4 *L4Filter) uint16
	GetSecurityIdentity() *identity.Identity
}

func getSecurityIdentities(labelsMap cache.IdentityCache, selector *api.EndpointSelector) []identity.NumericIdentity {
	identities := make([]identity.NumericIdentity, 0, len(labelsMap))
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

// DistillPolicy filters down the specified SelectorPolicy (which acts upon
// selectors) into a set of concrete map entries based on the specified
// identityCache. These can subsequently be plumbed into the datapath.
//
// Must be performed while holding the Repository lock.
func (p *SelectorPolicy) DistillPolicy(policyOwner PolicyOwner, identityCache cache.IdentityCache) *EndpointPolicy {

	calculatedPolicy := &EndpointPolicy{
		SelectorPolicy:          p,
		PolicyMapState:          make(MapState),
		PolicyOwner:             policyOwner,
		DeniedIngressIdentities: cache.IdentityCache{},
		DeniedEgressIdentities:  cache.IdentityCache{},
	}

	labels := policyOwner.GetSecurityIdentity().LabelArray
	ingressCtx := SearchContext{
		To:                            labels,
		rulesSelect:                   true,
		skipL4RequirementsAggregation: true,
	}

	egressCtx := SearchContext{
		From:                          labels,
		rulesSelect:                   true,
		skipL4RequirementsAggregation: true,
	}

	if option.Config.TracingEnabled() {
		ingressCtx.Trace = TRACE_ENABLED
		egressCtx.Trace = TRACE_ENABLED
	}

	if p.IngressPolicyEnabled {
		for identity, labels := range identityCache {
			ingressCtx.From = labels
			egressCtx.To = labels

			ingressAccess := p.matchingRules.canReachIngressRLocked(&ingressCtx)
			if ingressAccess == api.Allowed {
				keyToAdd := Key{
					Identity:         identity.Uint32(),
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}
				calculatedPolicy.PolicyMapState[keyToAdd] = MapStateEntry{}
			} else if ingressAccess == api.Denied {
				calculatedPolicy.DeniedIngressIdentities[identity] = labels
			}
		}
	} else {
		calculatedPolicy.PolicyMapState.AllowAllIdentities(identityCache, trafficdirection.Ingress)
	}

	if p.EgressPolicyEnabled {
		for identity, labels := range identityCache {
			egressCtx.To = labels

			egressAccess := p.matchingRules.canReachEgressRLocked(&egressCtx)
			if egressAccess == api.Allowed {
				keyToAdd := Key{
					Identity:         identity.Uint32(),
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}
				calculatedPolicy.PolicyMapState[keyToAdd] = MapStateEntry{}
			} else if egressAccess == api.Denied {
				calculatedPolicy.DeniedEgressIdentities[identity] = labels
			}
		}
	} else {
		calculatedPolicy.PolicyMapState.AllowAllIdentities(identityCache, trafficdirection.Egress)
	}

	calculatedPolicy.computeDesiredL4PolicyMapEntries(identityCache)
	calculatedPolicy.PolicyMapState.DetermineAllowLocalhost(p.L4Policy)

	return calculatedPolicy
}

// computeDesiredL4PolicyMapEntries transforms the EndpointPolicy.L4Policy into
// the datapath-friendly format inside EndpointPolicy.PolicyMapState.
func (p *EndpointPolicy) computeDesiredL4PolicyMapEntries(identityCache cache.IdentityCache) {

	if p.L4Policy == nil {
		return
	}
	p.computeDirectionL4PolicyMapEntries(identityCache, p.L4Policy.Ingress, trafficdirection.Ingress, p.DeniedIngressIdentities)
	p.computeDirectionL4PolicyMapEntries(identityCache, p.L4Policy.Egress, trafficdirection.Egress, p.DeniedEgressIdentities)
	return
}

func (p *EndpointPolicy) computeDirectionL4PolicyMapEntries(identityCache cache.IdentityCache, l4PolicyMap L4PolicyMap, direction trafficdirection.TrafficDirection, deniedIdentities cache.IdentityCache) {
	for _, filter := range l4PolicyMap {
		keysFromFilter := filter.ToKeys(direction, identityCache, deniedIdentities)
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
			p.PolicyMapState[keyFromFilter] = MapStateEntry{ProxyPort: proxyPort}
		}
	}
}

// NewEndpointPolicy returns an empty EndpointPolicy stub.
func NewEndpointPolicy() *EndpointPolicy {
	return &EndpointPolicy{
		SelectorPolicy: &SelectorPolicy{},
	}
}

// Realizes copies the fields from desired into p. It assumes that the fields in
// desired are not modified after this function is called.
func (p *SelectorPolicy) Realizes(desired *SelectorPolicy) {
	if p == nil {
		p = &SelectorPolicy{}
	}
	p.IngressPolicyEnabled = desired.IngressPolicyEnabled
	p.EgressPolicyEnabled = desired.EgressPolicyEnabled
	p.L4Policy = desired.L4Policy
	p.CIDRPolicy = desired.CIDRPolicy
}

// Realizes copies the fields from desired into p. It assumes that the fields in
// desired are not modified after this function is called.
func (p *EndpointPolicy) Realizes(desired *EndpointPolicy) {
	if p == nil {
		p = NewEndpointPolicy()
	}

	p.SelectorPolicy.Realizes(desired.SelectorPolicy)
	p.DeniedEgressIdentities = desired.DeniedEgressIdentities
	p.DeniedIngressIdentities = desired.DeniedIngressIdentities
}
