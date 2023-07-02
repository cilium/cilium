// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"github.com/sirupsen/logrus"

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
	L4Policy L4Policy

	// IngressPolicyEnabled specifies whether this policy contains any policy
	// at ingress.
	IngressPolicyEnabled bool

	// EgressPolicyEnabled specifies whether this policy contains any policy
	// at egress.
	EgressPolicyEnabled bool
}

func (p *selectorPolicy) Attach(ctx PolicyContext) {
	p.L4Policy.Attach(ctx)
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
// Endpoint mutex must not be held when these are called!
type PolicyOwner interface {
	// GetID returns the endpoint ID.
	// Does not take the endpoint lock.
	GetID() uint64

	// LookupRedirectPort returns the redirect port of an already existing redirect.
	// This is to be used for incremental updates due to changes in identities.
	// Current implementation of this takes the Endpoint lock.
	LookupRedirectPort(ingress bool, protocol string, port uint16) uint16

	// GetRedirectPort returns the redirect port of a redirect that may be created or updated
	// during this call based on 'l4'
	// Current implementation of this does not take the Endpoint lock.
	GetRedirectPort(l4 *L4Filter) (uint16, ChangeState)

	// GetNamedPort returns the port number for the given named port, or 0 if undefined.
	// Does not take the endpoint lock.
	GetNamedPort(ingress bool, name string, proto uint8) uint16

	// PolicyDebug logs 'msg' with 'fields' if debug logging is enabled. These logs are normally
	// separate from the main Cilium Agent logs.
	// Does not take the endpoint lock.
	PolicyDebug(fields logrus.Fields, msg string)
}

// newSelectorPolicy returns an empty selectorPolicy stub.
func newSelectorPolicy(selectorCache *SelectorCache) *selectorPolicy {
	return &selectorPolicy{
		Revision:      0,
		SelectorCache: selectorCache,
		L4Policy:      NewL4Policy(0),
	}
}

// insertUser adds a user to the L4Policy so that incremental
// updates of the L4Policy may be fowarded.
func (p *selectorPolicy) insertUser(user *EndpointPolicy) {
	p.L4Policy.insertUser(user)
}

// removeUser removes a user from the L4Policy so the EndpointPolicy
// can be freed when not needed any more
func (p *selectorPolicy) removeUser(user *EndpointPolicy) {
	p.L4Policy.removeUser(user)
}

// Detach releases resources held by a selectorPolicy to enable
// successful eventual GC.  Note that the selectorPolicy itself if not
// modified in any way, so that it can be used concurrently.
func (p *selectorPolicy) Detach() {
	p.L4Policy.Detach(p.SelectorCache)
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
	p.SelectorCache.mutex.RLock()
	calculatedPolicy.toMapState()
	if !isHost {
		calculatedPolicy.PolicyMapState.DetermineAllowLocalhostIngress()
	}
	p.SelectorCache.mutex.RUnlock()

	return calculatedPolicy
}

// Detach removes EndpointPolicy references from selectorPolicy
// to allow the EndpointPolicy to be GC'd.
// PolicyOwner (aka Endpoint) is also locked during this call.
func (p *EndpointPolicy) Detach() {
	p.selectorPolicy.removeUser(p)
}

// computeDesiredL4PolicyMapEntries transforms the EndpointPolicy.L4Policy into
// the datapath-friendly format inside EndpointPolicy.PolicyMapState.
// Called with selectorcache locked for reading
func (p *EndpointPolicy) toMapState() {
	p.L4Policy.Ingress.toMapState(p)
	p.L4Policy.Egress.toMapState(p)
}

// Called with selectorcache locked for reading
func (l4policy L4DirectionPolicy) toMapState(p *EndpointPolicy) {
	redirects := make([]*L4Filter, 0, len(l4policy.PortRules))
	for _, l4 := range l4policy.PortRules {
		if l4.L7Parser != ParserTypeNone {
			redirects = append(redirects, l4)
			continue
		}
		l4.toMapState(p, l4policy.features, 0, ChangeState{})
	}
	// Process redirect filters after non-redirects so that the effects of redirects can be
	// tracked consistently
	for _, l4 := range redirects {
		// Resolve the proxy port for this l4Filter
		redirectPort, proxyChanges := p.PolicyOwner.GetRedirectPort(l4)
		l4.toMapState(p, l4policy.features, redirectPort, proxyChanges)
	}
}

// ConsumeMapChanges transfers the changes from MapChanges to the caller,
// locking the selector cache to make sure concurrent identity updates
// have completed.
// PolicyOwner (aka Endpoint) is also locked during this call.
func (p *EndpointPolicy) ConsumeMapChanges() (adds, deletes Keys) {
	p.selectorPolicy.SelectorCache.mutex.Lock()
	defer p.selectorPolicy.SelectorCache.mutex.Unlock()
	features := p.selectorPolicy.L4Policy.Ingress.features | p.selectorPolicy.L4Policy.Egress.features
	return p.policyMapChanges.consumeMapChanges(p.PolicyMapState, features, p.SelectorCache)
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
		selectorPolicy: newSelectorPolicy(repo.GetSelectorCache()),
	}
}
