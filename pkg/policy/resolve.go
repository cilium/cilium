// Copyright 2018-2020 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

// selectorPolicy is a structure which contains the resolved policy for a
// particular Identity across all layers (L3, L4, and L7), with the policy
// still determined in terms of EndpointSelectors.
type selectorPolicy struct {
	// Revision is the revision of the policy repository used to generate
	// this selectorPolicy.
	Revision uint64

	// SelectorCache managing selectors in L4Policy
	SelectorCache *SelectorCache

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
}

func (p *selectorPolicy) Attach(ctx PolicyContext) {
	if p.L4Policy != nil {
		p.L4Policy.Attach(ctx)
	}
}

// EndpointPolicy is a structure which contains the resolved policy across all
// layers (L3, L4, and L7), distilled against a set of identities.
type EndpointPolicy struct {
	// Note that all Endpoints sharing the same identity will be
	// referring to a shared selectorPolicy!
	*selectorPolicy

	// PolicyMapState contains the state of this policy as it relates to the
	// datapath. In the future, this will be factored out of this object to
	// decouple the policy as it relates to the datapath vs. its userspace
	// representation.
	// It maps each Key to the proxy port if proxy redirection is needed.
	// Proxy port 0 indicates no proxy redirection.
	// All fields within the Key and the proxy port must be in host byte-order.
	// Must only be accessed with PolicyOwner (aka Endpoint) lock taken.
	PolicyMapState MapState

	// policyMapChanges collects pending changes to the PolicyMapState
	policyMapChanges MapChanges

	// PolicyOwner describes any type which consumes this EndpointPolicy object.
	PolicyOwner PolicyOwner
}

// PolicyOwner is anything which consumes a EndpointPolicy.
type PolicyOwner interface {
	GetID() uint64
	LookupRedirectPortLocked(ingress bool, protocol string, port uint16) uint16
	GetNamedPort(ingress bool, name string, proto uint8) uint16
	GetNamedPortLocked(ingress bool, name string, proto uint8) uint16
}

// newSelectorPolicy returns an empty selectorPolicy stub.
func newSelectorPolicy(revision uint64, selectorCache *SelectorCache) *selectorPolicy {
	return &selectorPolicy{
		Revision:      revision,
		SelectorCache: selectorCache,
	}
}

// insertUser adds a user to the L4Policy so that incremental
// updates of the L4Policy may be fowarded.
func (p *selectorPolicy) insertUser(user *EndpointPolicy) {
	if p.L4Policy != nil {
		p.L4Policy.insertUser(user)
	}
}

// Detach releases resources held by a selectorPolicy to enable
// successful eventual GC.  Note that the selectorPolicy itself if not
// modified in any way, so that it can be used concurrently.
func (p *selectorPolicy) Detach() {
	if p.L4Policy != nil {
		p.L4Policy.Detach(p.SelectorCache)
	}
}

// DistillPolicy filters down the specified selectorPolicy (which acts
// upon selectors) into a set of concrete map entries based on the
// SelectorCache. These can subsequently be plumbed into the datapath.
//
// Must be performed while holding the Repository lock.
// PolicyOwner (aka Endpoint) is also locked during this call.
func (p *selectorPolicy) DistillPolicy(policyOwner PolicyOwner, isHost bool) *EndpointPolicy {
	calculatedPolicy := &EndpointPolicy{
		selectorPolicy: p,
		PolicyMapState: make(MapState),
		PolicyOwner:    policyOwner,
	}

	if !p.IngressPolicyEnabled || !p.EgressPolicyEnabled {
		calculatedPolicy.PolicyMapState.AllowAllIdentities(
			!p.IngressPolicyEnabled, !p.EgressPolicyEnabled)
	}

	// Register the new EndpointPolicy as a receiver of delta
	// updates.  Any updates happening after this, but before
	// computeDesiredL4PolicyMapEntries() call finishes may
	// already be applied to the PolicyMapState, specifically:
	//
	// - policyMapChanges may contain an addition of an entry that
	//   is already added to the PolicyMapState
	//
	// - policyMapChanges may contain a deletion of an entry that
	//   has already been deleted from PolicyMapState
	p.insertUser(calculatedPolicy)

	// Must come after the 'insertUser()' above to guarantee
	// PolicyMapChanges will contain all changes that are applied
	// after the computation of PolicyMapState has started.
	calculatedPolicy.computeDesiredL4PolicyMapEntries()
	if !isHost {
		calculatedPolicy.PolicyMapState.DetermineAllowLocalhostIngress()
	}

	return calculatedPolicy
}

// computeDesiredL4PolicyMapEntries transforms the EndpointPolicy.L4Policy into
// the datapath-friendly format inside EndpointPolicy.PolicyMapState.
func (p *EndpointPolicy) computeDesiredL4PolicyMapEntries() {

	if p.L4Policy == nil {
		return
	}
	p.computeDirectionL4PolicyMapEntries(p.PolicyMapState, p.L4Policy.Ingress, trafficdirection.Ingress)
	p.computeDirectionL4PolicyMapEntries(p.PolicyMapState, p.L4Policy.Egress, trafficdirection.Egress)
}

func (p *EndpointPolicy) computeDirectionL4PolicyMapEntries(policyMapState MapState, l4PolicyMap L4PolicyMap, direction trafficdirection.TrafficDirection) {
	for _, filter := range l4PolicyMap {
		lookupDone := false
		proxyport := uint16(0)
		keysFromFilter := filter.ToMapState(p.PolicyOwner, direction)
		for keyFromFilter, entry := range keysFromFilter {
			// Fix up the proxy port for entries that need proxy redirection
			if entry.IsRedirectEntry() {
				if !lookupDone {
					// only lookup once for each filter
					// Use 'destPort' from the key as it is already resolved
					// from a named port if needed.
					proxyport = p.PolicyOwner.LookupRedirectPortLocked(filter.Ingress, string(filter.Protocol), keyFromFilter.DestPort)
					lookupDone = true
				}
				entry.ProxyPort = proxyport
				// If the currently allocated proxy port is 0, this is a new
				// redirect, for which no port has been allocated yet. Ignore
				// it for now. This will be configured by
				// e.addNewRedirectsFromDesiredPolicy() once the port has been allocated.
				if !entry.IsRedirectEntry() {
					continue
				}
			}
			policyMapState.DenyPreferredInsert(keyFromFilter, entry)
		}
	}
}

// ConsumeMapChanges transfers the changes from MapChanges to the caller,
// locking the selector cache to make sure concurrent identity updates
// have completed.
// PolicyOwner (aka Endpoint) is also locked during this call.
func (p *EndpointPolicy) ConsumeMapChanges() (adds, deletes MapState) {
	p.selectorPolicy.SelectorCache.mutex.Lock()
	defer p.selectorPolicy.SelectorCache.mutex.Unlock()
	return p.policyMapChanges.consumeMapChanges(p.PolicyMapState)
}

// AllowsIdentity returns whether the specified policy allows
// ingress and egress traffic for the specified numeric security identity.
// If the 'secID' is zero, it will check if all traffic is allowed.
//
// Returning true for either return value indicates all traffic is allowed.
func (p *EndpointPolicy) AllowsIdentity(identity identity.NumericIdentity) (ingress, egress bool) {
	key := Key{
		Identity: uint32(identity),
	}

	if !p.IngressPolicyEnabled {
		ingress = true
	} else {
		key.TrafficDirection = trafficdirection.Ingress.Uint8()
		if v, exists := p.PolicyMapState[key]; exists && !v.IsDeny {
			ingress = true
		}
	}

	if !p.EgressPolicyEnabled {
		egress = true
	} else {
		key.TrafficDirection = trafficdirection.Egress.Uint8()
		if v, exists := p.PolicyMapState[key]; exists && !v.IsDeny {
			egress = true
		}
	}

	return ingress, egress
}

// NewEndpointPolicy returns an empty EndpointPolicy stub.
func NewEndpointPolicy(repo *Repository) *EndpointPolicy {
	return &EndpointPolicy{
		selectorPolicy: newSelectorPolicy(0, repo.GetSelectorCache()),
	}
}
