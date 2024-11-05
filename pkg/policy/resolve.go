// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"iter"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/u8proto"
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

	// VersionHandle represents the version of the SelectorCache 'policyMapState' was generated
	// from.
	// Changes after this version appear in 'policyMapChanges'.
	// This is updated when incremental changes are applied.
	VersionHandle *versioned.VersionHandle

	// policyMapState contains the state of this policy as it relates to the
	// datapath. In the future, this will be factored out of this object to
	// decouple the policy as it relates to the datapath vs. its userspace
	// representation.
	// It maps each Key to the proxy port if proxy redirection is needed.
	// Proxy port 0 indicates no proxy redirection.
	// All fields within the Key and the proxy port must be in host byte-order.
	// Must only be accessed with PolicyOwner (aka Endpoint) lock taken.
	policyMapState *mapState

	// policyMapChanges collects pending changes to the PolicyMapState
	policyMapChanges MapChanges

	// PolicyOwner describes any type which consumes this EndpointPolicy object.
	PolicyOwner PolicyOwner

	// Redirects contains the proxy ports needed for this EndpointPolicy.
	// If any redirects are missing a new policy will be computed to rectify it, so this is
	// constant for the lifetime of this EndpointPolicy.
	Redirects map[string]uint16
}

// LookupRedirectPort returns the redirect L4 proxy port for the given input parameters.
// Returns 0 if not found or the filter doesn't require a redirect.
// Returns an error if the redirect port can not be found.
// This is called when accumulating incremental map changes, endpoint lock must not be taken.
func (p *EndpointPolicy) LookupRedirectPort(ingress bool, protocol string, port uint16, listener string) (uint16, error) {
	proxyID := ProxyID(uint16(p.PolicyOwner.GetID()), ingress, protocol, port, listener)
	if proxyPort, exists := p.Redirects[proxyID]; exists {
		return proxyPort, nil
	}
	return 0, fmt.Errorf("Proxy port for redirect %q not found", proxyID)
}

// PolicyOwner is anything which consumes a EndpointPolicy.
type PolicyOwner interface {
	GetID() uint64
	GetNamedPort(ingress bool, name string, proto u8proto.U8proto) uint16
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
func (p *selectorPolicy) DistillPolicy(policyOwner PolicyOwner, redirects map[string]uint16, isHost bool) *EndpointPolicy {
	var calculatedPolicy *EndpointPolicy

	// EndpointPolicy is initialized while 'GetCurrentVersionHandleFunc' keeps the selector
	// cache write locked. This syncronizes the SelectorCache handle creation and the insertion
	// of the new policy to the selectorPolicy before any new incremental updated can be
	// generated.
	//
	// With this we have to following guarantees:
	// - Selections seen with the 'version' are the ones available at the time of the 'version'
	//   creation, and the IDs therein have been applied to all Selectors cached at the time.
	// - All further incremental updates are delivered to 'policyMapChanges' as whole
	//   transactions, i.e, changes to all selectors due to addition or deletion of new/old
	//   identities are visible in the set of changes processed and returned by
	//   ConsumeMapChanges().
	p.SelectorCache.GetVersionHandleFunc(func(version *versioned.VersionHandle) {
		calculatedPolicy = &EndpointPolicy{
			selectorPolicy: p,
			VersionHandle:  version,
			policyMapState: newMapState(),
			policyMapChanges: MapChanges{
				firstVersion: version.Version(),
			},
			PolicyOwner: policyOwner,
			Redirects:   redirects,
		}
		// Register the new EndpointPolicy as a receiver of incremental
		// updates before selector cache lock is released by 'GetCurrentVersionHandleFunc'.
		p.insertUser(calculatedPolicy)
	})

	if !p.IngressPolicyEnabled || !p.EgressPolicyEnabled {
		calculatedPolicy.policyMapState.allowAllIdentities(
			!p.IngressPolicyEnabled, !p.EgressPolicyEnabled)
	}

	// Must come after the 'insertUser()' above to guarantee
	// PolicyMapChanges will contain all changes that are applied
	// after the computation of PolicyMapState has started.
	calculatedPolicy.toMapState()
	if !isHost {
		calculatedPolicy.policyMapState.determineAllowLocalhostIngress()
	}

	return calculatedPolicy
}

// Ready releases the handle on a selector cache version so that stale state can be released.
// This should be called when the policy has been realized.
func (p *EndpointPolicy) Ready() (err error) {
	// release resources held for this version
	err = p.VersionHandle.Close()
	p.VersionHandle = nil
	return err
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
	m, ok := ms.(*mapState)
	if !ok || m == nil {
		p.policyMapState = newMapState()
		return
	}
	p.policyMapState = m
}

// Detach removes EndpointPolicy references from selectorPolicy
// to allow the EndpointPolicy to be GC'd.
// PolicyOwner (aka Endpoint) is also locked during this call.
func (p *EndpointPolicy) Detach() {
	p.selectorPolicy.removeUser(p)
	// in case the call was missed previouly
	if p.Ready() == nil {
		// succeeded, so it was missed previously
		log.Warningf("Detach: EndpointPolicy was not marked as Ready")
	}
	// Also release the version handle held for incremental updates, if any.
	// This must be done after the removeUser() call above, so that we do not get a new version
	// handles any more!
	p.policyMapChanges.detach()
}

// NewMapStateWithInsert returns a new MapState and an insert function that can be used to populate
// it. We keep general insert functions private so that the caller can only insert to this specific
// map.
func NewMapStateWithInsert() (MapState, func(k Key, e MapStateEntry)) {
	currentMap := newMapState()

	return currentMap, func(k Key, e MapStateEntry) {
		currentMap.insert(k, e)
	}
}

func (p *EndpointPolicy) InsertMapState(key Key, entry MapStateEntry) {
	// SelectorCache used as Identities interface which only has GetPrefix() that needs no lock
	p.policyMapState.insert(key, entry)
}

func (p *EndpointPolicy) DeleteMapState(key Key) {
	// SelectorCache used as Identities interface which only has GetPrefix() that needs no lock
	p.policyMapState.delete(key)
}

func (p *EndpointPolicy) RevertChanges(changes ChangeState) {
	// SelectorCache used as Identities interface which only has GetPrefix() that needs no lock
	p.policyMapState.revertChanges(changes)
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
		l4.toMapState(p, l4policy.features, ChangeState{})
		return true
	})
}

// RedirectFilters returns an iterator for each L4Filter with a redirect in the policy.
func (p *selectorPolicy) RedirectFilters() iter.Seq2[*L4Filter, *PerSelectorPolicy] {
	return func(yield func(*L4Filter, *PerSelectorPolicy) bool) {
		if p.L4Policy.Ingress.forEachRedirectFilter(yield) {
			p.L4Policy.Egress.forEachRedirectFilter(yield)
		}
	}
}

func (l4policy L4DirectionPolicy) forEachRedirectFilter(yield func(*L4Filter, *PerSelectorPolicy) bool) bool {
	ok := true
	l4policy.PortRules.ForEach(func(l4 *L4Filter) bool {
		if l4.IsRedirect() {
			for _, ps := range l4.PerSelectorPolicies {
				if ps != nil && ps.IsRedirect() {
					ok = yield(l4, ps)
				}
			}
		}
		return ok
	})
	return ok
}

// ConsumeMapChanges transfers the changes from MapChanges to the caller.
// SelectorCache used as Identities interface which only has GetPrefix() that needs no lock.
// Endpoints explicitly wait for a WaitGroup signaling completion of AccumulatePolicyMapChanges
// calls before calling ConsumeMapChanges so that if we see any partial changes here, there will be
// another call after to cover for the rest.
// PolicyOwner (aka Endpoint) is locked during this call.
// Caller is responsible for calling the returned 'closer' to release resources held for the new version!
// 'closer' may not be called while selector cache is locked!
func (p *EndpointPolicy) ConsumeMapChanges() (closer func(), changes ChangeState) {
	features := p.selectorPolicy.L4Policy.Ingress.features | p.selectorPolicy.L4Policy.Egress.features
	version, changes := p.policyMapChanges.consumeMapChanges(p, features)

	closer = func() {}
	if version.IsValid() {
		var msg string
		// update the version handle in p.VersionHandle so that any follow-on processing
		// acts on the basis of the new version
		if p.VersionHandle.IsValid() {
			p.VersionHandle.Close()
			msg = "ConsumeMapChanges: updated valid version"
		} else {
			closer = func() {
				// p.VersionHandle was not valid, close it
				p.Ready()
			}
			msg = "ConsumeMapChanges: new incremental version"
		}
		p.VersionHandle = version

		p.PolicyOwner.PolicyDebug(logrus.Fields{
			logfields.Version: version,
			logfields.Changes: changes,
		}, msg)
	}

	return closer, changes
}

// NewEndpointPolicy returns an empty EndpointPolicy stub.
func NewEndpointPolicy(repo PolicyRepository) *EndpointPolicy {
	return &EndpointPolicy{
		selectorPolicy: newSelectorPolicy(repo.GetSelectorCache()),
		policyMapState: newMapState(),
	}
}
