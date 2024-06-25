// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"github.com/sirupsen/logrus"
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

	// policyMapState contains the state of this policy as it relates to the
	// datapath. In the future, this will be factored out of this object to
	// decouple the policy as it relates to the datapath vs. its userspace
	// representation.
	// It maps each Key to the proxy port if proxy redirection is needed.
	// Proxy port 0 indicates no proxy redirection.
	// All fields within the Key and the proxy port must be in host byte-order.
	// Must only be accessed with PolicyOwner (aka Endpoint) lock taken.
	policyMapState MapState

	// policyMapChanges collects pending changes to the PolicyMapState
	policyMapChanges MapChanges

	// PolicyOwner describes any type which consumes this EndpointPolicy object.
	PolicyOwner PolicyOwner
}

// PolicyOwner is anything which consumes a EndpointPolicy.
type PolicyOwner interface {
	GetID() uint64
	LookupRedirectPort(ingress bool, protocol string, port uint16, listener string) (uint16, error)
	GetRealizedRedirects() map[string]uint16
	HasBPFPolicyMap() bool
	GetNamedPort(ingress bool, name string, proto uint8) uint16
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
// Called without holding the Selector cache or Repository locks.
// PolicyOwner (aka Endpoint) is also unlocked during this call,
// but the Endpoint's build mutex is held.
func (p *selectorPolicy) DistillPolicy(policyOwner PolicyOwner, isHost bool) *EndpointPolicy {
	calculatedPolicy := &EndpointPolicy{
		selectorPolicy: p,
		policyMapState: NewMapState(nil),
		PolicyOwner:    policyOwner,
	}

	if !p.IngressPolicyEnabled || !p.EgressPolicyEnabled {
		calculatedPolicy.policyMapState.allowAllIdentities(
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
	calculatedPolicy.toMapState()
	if !isHost {
		calculatedPolicy.policyMapState.determineAllowLocalhostIngress()
	}

	return calculatedPolicy
}

// GetPolicyMap gets the policy map state as the interface
// MapState
func (p *EndpointPolicy) GetPolicyMap() MapState {
	return p.policyMapState
}

// SetPolicyMap sets the policy map state as the interface
// MapState. If the main argument is nil, then this method
// will initialize a new MapState object for the caller.
func (p *EndpointPolicy) SetPolicyMap(ms MapState) {
	if ms == nil {
		p.policyMapState = NewMapState(nil)
		return
	}
	p.policyMapState = ms
}

// Detach removes EndpointPolicy references from selectorPolicy
// to allow the EndpointPolicy to be GC'd.
// PolicyOwner (aka Endpoint) is also locked during this call.
func (p *EndpointPolicy) Detach() {
	p.selectorPolicy.removeUser(p)
}

// toMapState transforms the EndpointPolicy.L4Policy into
// the datapath-friendly format inside EndpointPolicy.PolicyMapState.
// Called with selectorcache locked for reading.
// Called without holding the Repository lock.
// PolicyOwner (aka Endpoint) is also unlocked during this call,
// but the Endpoint's build mutex is held.
func (p *EndpointPolicy) toMapState() {
	p.L4Policy.Ingress.toMapState(p)
	p.L4Policy.Egress.toMapState(p)
}

// toMapState transforms the L4DirectionPolicy into
// the datapath-friendly format inside EndpointPolicy.PolicyMapState.
// Called with selectorcache locked for reading.
// Called without holding the Repository lock.
// PolicyOwner (aka Endpoint) is also unlocked during this call,
// but the Endpoint's build mutex is held.
func (l4policy L4DirectionPolicy) toMapState(p *EndpointPolicy) {
	l4policy.PortRules.ForEach(func(l4 *L4Filter) bool {
		l4.toMapState(p, l4policy.features, p.PolicyOwner.GetRealizedRedirects(), ChangeState{})
		return true
	})
}

// createRedirectsFunc returns 'nil' if map changes should not be applied immemdiately,
// otherwise the returned map is to be used to find redirect ports for map updates.
type createRedirectsFunc func(*L4Filter) map[string]uint16

// UpdateRedirects updates redirects in the EndpointPolicy's PolicyMapState by using the provided
// function to create redirects. Changes to 'p.PolicyMapState' are collected in
// 'adds' and 'updated' so that they can be reverted when needed.
func (p *EndpointPolicy) UpdateRedirects(ingress bool, createRedirects createRedirectsFunc, changes ChangeState) {
	l4policy := &p.L4Policy.Ingress
	if ingress {
		l4policy = &p.L4Policy.Egress
	}

	l4policy.updateRedirects(p, createRedirects, changes)
}

func (l4policy L4DirectionPolicy) updateRedirects(p *EndpointPolicy, createRedirects createRedirectsFunc, changes ChangeState) {
	l4policy.PortRules.ForEach(func(l4 *L4Filter) bool {
		if l4.IsRedirect() {
			// Check if we are denying this specific L4 first regardless the L3, if there are any deny policies
			if l4policy.features.contains(denyRules) && p.policyMapState.deniesL4(p.PolicyOwner, l4) {
				return true
			}

			redirects := createRedirects(l4)
			if redirects != nil {
				// Set the proxy port in the policy map.
				l4.toMapState(p, l4policy.features, redirects, changes)
			}
		}
		return true
	})
}

// ConsumeMapChanges transfers the changes from MapChanges to the caller.
// SelectorCache used as Identities interface which only has GetPrefix() that needs no lock.
// Endpoints explicitly wait for a WaitGroup signaling completion of AccumulatePolicyMapChanges
// calls before calling ConsumeMapChanges so that if we see any partial changes here, there will be
// another call after to cover for the rest.
// PolicyOwner (aka Endpoint) is locked during this call.
func (p *EndpointPolicy) ConsumeMapChanges() (adds, deletes Keys) {
	features := p.selectorPolicy.L4Policy.Ingress.features | p.selectorPolicy.L4Policy.Egress.features
	return p.policyMapChanges.consumeMapChanges(p.PolicyOwner, p.policyMapState, features, p.SelectorCache)
}

// NewEndpointPolicy returns an empty EndpointPolicy stub.
func NewEndpointPolicy(repo *Repository) *EndpointPolicy {
	return &EndpointPolicy{
		selectorPolicy: newSelectorPolicy(repo.GetSelectorCache()),
		policyMapState: NewMapState(nil),
	}
}
