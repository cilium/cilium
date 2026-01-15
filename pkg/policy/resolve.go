// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"runtime"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"

	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

// PolicyContext is an interface policy resolution functions use to access the Repository.
// This way testing code can run without mocking a full Repository.
type PolicyContext interface {
	// AllowLocalhost returns true if policy should allow ingress from local host.
	// Always returns false for egress.
	AllowLocalhost() bool

	// return the namespace in which the policy rule is being resolved
	GetNamespace() string

	// return the SelectorCache
	GetSelectorCache() *SelectorCache

	// GetTLSContext resolves the given 'api.TLSContext' into CA
	// certs and the public and private keys, using secrets from
	// k8s or from the local file system.
	GetTLSContext(tls *api.TLSContext) (ca, public, private string, inlineSecrets bool, err error)

	// GetEnvoyHTTPRules translates the given 'api.L7Rules' into
	// the protobuf representation the Envoy can consume. The bool
	// return parameter tells whether the rule enforcement can
	// be short-circuited upon the first allowing rule. This is
	// false if any of the rules has side-effects, requiring all
	// such rules being evaluated.
	GetEnvoyHTTPRules(l7Rules *api.L7Rules) (*cilium.HttpNetworkPolicyRules, bool)

	// SetPriority sets the priority level for the first rule being processed.
	SetPriority(tier types.Tier, priority types.Priority)

	// Priority returns the priority level for the current rule.
	Priority() (tier types.Tier, priority types.Priority)

	// DefaultDenyIngress returns true if default deny is enabled for ingress
	DefaultDenyIngress() bool

	// DefaultDenyEgress returns true if default deny is enabled for egress
	DefaultDenyEgress() bool

	SetOrigin(ruleOrigin)
	Origin() ruleOrigin

	GetLogger() *slog.Logger

	PolicyTrace(format string, a ...any)
}

type policyContext struct {
	repo *Repository
	ns   string

	// Policy tier, 0 is the default and highest tier.
	tier types.Tier

	// priority level for the rule being processed, 0 is the highest priority.
	priority types.Priority

	defaultDenyIngress bool
	defaultDenyEgress  bool

	origin ruleOrigin

	logger       *slog.Logger
	traceEnabled bool
}

var _ PolicyContext = &policyContext{}

func (p *policyContext) AllowLocalhost() bool {
	return option.Config.AlwaysAllowLocalhost()
}

// GetNamespace() returns the namespace for the policy rule being resolved
func (p *policyContext) GetNamespace() string {
	return p.ns
}

// GetSelectorCache() returns the selector cache used by the Repository
func (p *policyContext) GetSelectorCache() *SelectorCache {
	return p.repo.GetSelectorCache()
}

// GetTLSContext() returns data for TLS Context via a CertificateManager
func (p *policyContext) GetTLSContext(tls *api.TLSContext) (ca, public, private string, inlineSecrets bool, err error) {
	if p.repo.certManager == nil {
		return "", "", "", false, fmt.Errorf("No Certificate Manager set on Policy Repository")
	}
	return p.repo.certManager.GetTLSContext(context.TODO(), tls, p.ns)
}

func (p *policyContext) GetEnvoyHTTPRules(l7Rules *api.L7Rules) (*cilium.HttpNetworkPolicyRules, bool) {
	return p.repo.GetEnvoyHTTPRules(l7Rules, p.ns)
}

// SetPriority sets the tier and priority for the first rule being processed.
func (p *policyContext) SetPriority(tier types.Tier, priority types.Priority) {
	p.tier = tier
	p.priority = priority
}

// Priority returns the tier and priority for the current rule.
func (p *policyContext) Priority() (types.Tier, types.Priority) {
	return p.tier, p.priority
}

// DefaultDenyIngress returns true if default deny is enabled for ingress
func (p *policyContext) DefaultDenyIngress() bool {
	return p.defaultDenyIngress
}

// DefaultDenyEgress returns true if default deny is enabled for egress
func (p *policyContext) DefaultDenyEgress() bool {
	return p.defaultDenyEgress
}

func (p *policyContext) SetOrigin(ro ruleOrigin) {
	p.origin = ro
}

func (p *policyContext) Origin() ruleOrigin {
	return p.origin
}

func (p *policyContext) GetLogger() *slog.Logger {
	return p.logger
}

func (p *policyContext) PolicyTrace(format string, a ...any) {
	if p.logger == nil || !p.traceEnabled {
		return
	}
	format = strings.TrimRight(format, " \t\n")
	p.logger.Info(fmt.Sprintf(format, a...))
}

// SelectorPolicy represents a selectorPolicy, previously resolved from
// the policy repository and ready to be distilled against a set of identities
// to compute datapath-level policy configuration.
type SelectorPolicy interface {
	// CreateRedirects is used to ensure the endpoint has created all the needed redirects
	// before a new EndpointPolicy is created.
	RedirectFilters() iter.Seq2[*L4Filter, PerSelectorPolicyTuple]

	// DistillPolicy returns the policy in terms of connectivity to peer
	// Identities.
	DistillPolicy(logger *slog.Logger, owner PolicyOwner, redirects map[string]uint16) *EndpointPolicy
}

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
	SelectorPolicy *selectorPolicy

	// selectors represents the version of the SelectorCache 'policyMapState' was generated
	// from.
	// Changes after this version appear in 'policyMapChanges'.
	// This is updated when incremental changes are applied and closed as soon as possible.
	selectors SelectorSnapshot

	// policyMapState contains the state of this policy as it relates to the
	// datapath. In the future, this will be factored out of this object to
	// decouple the policy as it relates to the datapath vs. its userspace
	// representation.
	// It maps each Key to the proxy port if proxy redirection is needed.
	// Proxy port 0 indicates no proxy redirection.
	// All fields within the Key and the proxy port must be in host byte-order.
	// Must only be accessed with PolicyOwner (aka Endpoint) lock taken.
	policyMapState mapState

	// policyMapChanges collects pending changes to the PolicyMapState
	policyMapChanges MapChanges

	// PolicyOwner describes any type which consumes this EndpointPolicy object.
	PolicyOwner PolicyOwner

	// Redirects contains the proxy ports needed for this EndpointPolicy.
	// If any redirects are missing a new policy will be computed to rectify it, so this is
	// constant for the lifetime of this EndpointPolicy.
	Redirects map[string]uint16
}

func (p *EndpointPolicy) GetPolicySelectors() SelectorSnapshot {
	return p.selectors
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

// Lookup finds the policy verdict applicable to the given 'key' using the same precedence logic
// between L3 and L4-only policies like the bpf datapath when both match the given 'key'.
// To be used in testing in place of the bpf datapath when full integration testing is not desired.
// Returns the closest matching covering policy entry, the labels of the rules that contributed to
// that verdict, and 'true' if found.
// Returns a deny entry when a match is not found, mirroring the datapath default deny behavior.
// 'key' must not have a wildcard identity or port.
func (p *EndpointPolicy) Lookup(key Key) (MapStateEntry, RuleMeta, bool) {
	entry, found := p.policyMapState.lookup(key)
	return entry.MapStateEntry, entry.derivedFromRules.Value(), found
}

// CopyMapStateFrom copies the policy map entries from m.
func (p *EndpointPolicy) CopyMapStateFrom(m MapStateMap) {
	for key, entry := range m {
		p.policyMapState.entries[key] = NewMapStateEntry(entry)
	}
}

// PolicyOwner is anything which consumes a EndpointPolicy.
type PolicyOwner interface {
	GetID() uint64
	GetNamedPort(ingress bool, name string, proto u8proto.U8proto) uint16
	PolicyDebug(msg string, attrs ...any)
	IsHost() bool
	MapStateSize() int
	RegenerateIfAlive(regenMetadata *regeneration.ExternalRegenerationMetadata) <-chan bool
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

// detach releases resources held by a selectorPolicy to enable
// successful eventual GC.  Note that the selectorPolicy itself if not
// modified in any way, so that it can be used concurrently.
// The endpointID argument is only necessary if isDelete is false.
// It ensures that detach does not call a regeneration trigger on
// the same endpoint that initiated a selector policy update.
func (p *selectorPolicy) detach(isDelete bool, endpointID uint64) {
	p.L4Policy.detach(p.SelectorCache, isDelete, endpointID)
}

// DistillPolicy filters down the specified selectorPolicy (which acts
// upon selectors) into a set of concrete map entries based on the
// SelectorCache. These can subsequently be plumbed into the datapath.
//
// Called without holding the Selector cache or Repository locks.
// PolicyOwner (aka Endpoint) is also unlocked during this call,
// but the Endpoint's build mutex is held.
func (p *selectorPolicy) DistillPolicy(logger *slog.Logger, policyOwner PolicyOwner, redirects map[string]uint16) *EndpointPolicy {
	var calculatedPolicy *EndpointPolicy

	// EndpointPolicy is initialized while 'WithRLock' keeps the selector cache read
	// locked. This syncronizes the selector snapshot creation and the registration of the new
	// EndpointPolicy as a user of the selectorPolicy 'p' before any new incremental updated can
	// be generated.
	//
	// With this we have to following two guarantees:
	// - Selections seen via 'selectors' are the ones available at the time of the
	//   EndpointPolicy creation, and the IDs therein have been applied to all Selectors cached
	//   at the time.
	// - All further incremental updates are delivered to 'EndpointPolicy.policyMapChanges'
	//   as whole transactions, i.e, changes to all selectors due to addition or deletion of
	//   new/old identities are visible in the set of changes processed and returned by
	//   ConsumeMapChanges().
	p.SelectorCache.WithRLock(func(sc *SelectorCache) {
		selectors := sc.GetSelectorSnapshot()
		calculatedPolicy = &EndpointPolicy{
			SelectorPolicy: p,
			selectors:      selectors,
			policyMapState: newMapState(logger, policyOwner.MapStateSize()),
			policyMapChanges: MapChanges{
				logger:   logger,
				firstRev: selectors.Revision,
			},
			PolicyOwner: policyOwner,
			Redirects:   redirects,
		}
		// Register the new EndpointPolicy as a receiver of incremental
		// updates before selector cache lock is released by 'WithRLock'.
		p.insertUser(calculatedPolicy)
	})

	if !p.IngressPolicyEnabled || !p.EgressPolicyEnabled {
		calculatedPolicy.policyMapState.allowAllIdentities(
			!p.IngressPolicyEnabled, !p.EgressPolicyEnabled)
	}

	// Must come after the 'insertUser()' above to guarantee
	// PolicyMapChanges will contain all changes that are applied
	// after the computation of PolicyMapState has started.
	p.L4Policy.Ingress.toMapState(logger, calculatedPolicy)
	p.L4Policy.Egress.toMapState(logger, calculatedPolicy)

	if !policyOwner.IsHost() {
		calculatedPolicy.policyMapState.determineAllowLocalhostIngress()
	}

	return calculatedPolicy
}

func (p *selectorPolicy) IsDetached() (bool, time.Time) {
	ptr := p.L4Policy.detachedTime.Load()
	if ptr == nil {
		return false, time.Time{}
	}
	return true, *ptr
}

var (
	ErrStaleSelectors = errors.New("stale selector snapshot")
)

// Ready releases memory held for the selector snapshot.
// This should be called when the policy has been realized.
func (p *EndpointPolicy) Ready() (err error) {
	if !p.selectors.IsValid() {
		return ErrStaleSelectors
	}
	// release resources held for this version
	p.selectors.Invalidate()
	return nil
}

// Detach removes EndpointPolicy references from selectorPolicy
// to allow the EndpointPolicy to be GC'd.
// PolicyOwner (aka Endpoint) is also locked during this call.
func (p *EndpointPolicy) Detach(logger *slog.Logger) {
	p.SelectorPolicy.removeUser(p)
	// in case the call was missed previouly
	if p.Ready() == nil {
		// succeeded, so it was missed previously
		_, file, line, _ := runtime.Caller(1)
		logger.Warn(
			"Detach: EndpointPolicy was not marked as Ready",
			logfields.File, file,
			logfields.Line, line,
		)
	}
	// Also release the selector snapshot held for incremental updates, if any.
	// This must be done after the removeUser() call above, so that we do not get any
	// more incremental updates!
	p.policyMapChanges.detach()
}

func (p *EndpointPolicy) Len() int {
	return p.policyMapState.Len()
}

func (p *EndpointPolicy) Get(key Key) (MapStateEntry, bool) {
	return p.policyMapState.Get(key)
}

var errMissingKey = errors.New("Key not found")

// GetRuleMeta returns the list of labels of the rules that contributed
// to the entry at this key.
func (p *EndpointPolicy) GetRuleMeta(k Key) (RuleMeta, error) {
	entry, ok := p.policyMapState.get(k)
	if !ok {
		return RuleMeta{}, errMissingKey
	}
	return entry.derivedFromRules.Value(), nil
}

func (p *EndpointPolicy) Entries() iter.Seq2[Key, MapStateEntry] {
	return func(yield func(Key, MapStateEntry) bool) {
		p.policyMapState.ForEach(yield)
	}
}

func (p *EndpointPolicy) Equals(other MapStateMap) bool {
	return p.policyMapState.Equals(other)
}

func (p *EndpointPolicy) Diff(expected MapStateMap) string {
	return p.policyMapState.Diff(expected)
}

func (p *EndpointPolicy) Empty() bool {
	return p.policyMapState.Empty()
}

// Updated returns an iterator for all key/entry pairs in 'p' that are either new or updated
// compared to the entries in 'realized'.
// Here 'realized' is another EndpointPolicy.
// This can be used to figure out which entries need to be added to or updated in 'realised'.
func (p *EndpointPolicy) Updated(realized *EndpointPolicy) iter.Seq2[Key, MapStateEntry] {
	return func(yield func(Key, MapStateEntry) bool) {
		p.policyMapState.ForEach(func(key Key, entry MapStateEntry) bool {
			if oldEntry, ok := realized.policyMapState.Get(key); !ok || oldEntry != entry {
				if !yield(key, entry) {
					return false
				}
			}
			return true
		})
	}
}

// Missing returns an iterator for all key/entry pairs in 'realized' that missing from 'p'.
// Here 'realized' is another EndpointPolicy.
// This can be used to figure out which entries in 'realised' need to be deleted.
func (p *EndpointPolicy) Missing(realized *EndpointPolicy) iter.Seq2[Key, MapStateEntry] {
	return func(yield func(Key, MapStateEntry) bool) {
		realized.policyMapState.ForEach(func(key Key, entry MapStateEntry) bool {
			// If key that is in realized state is not in desired state, just remove it.
			if _, ok := p.policyMapState.Get(key); !ok {
				if !yield(key, entry) {
					return false
				}
			}
			return true
		})
	}
}

// UpdatedMap returns an iterator for all key/entry pairs in 'p' that are either new or updated
// compared to the entries in 'realized'.
// Here 'realized' is MapStateMap.
// This can be used to figure out which entries need to be added to or updated in 'realised'.
func (p *EndpointPolicy) UpdatedMap(realized MapStateMap) iter.Seq2[Key, MapStateEntry] {
	return func(yield func(Key, MapStateEntry) bool) {
		p.policyMapState.ForEach(func(key Key, entry MapStateEntry) bool {
			if oldEntry, ok := realized[key]; !ok || oldEntry != entry {
				if !yield(key, entry) {
					return false
				}
			}
			return true
		})
	}
}

// Missing returns an iterator for all key/entry pairs in 'realized' that missing from 'p'.
// Here 'realized' is MapStateMap.
// This can be used to figure out which entries in 'realised' need to be deleted.
func (p *EndpointPolicy) MissingMap(realized MapStateMap) iter.Seq2[Key, MapStateEntry] {
	return func(yield func(Key, MapStateEntry) bool) {
		for k, v := range realized {
			// If key that is in realized state is not in desired state, just remove it.
			if _, ok := p.policyMapState.Get(k); !ok {
				if !yield(k, v) {
					break
				}
			}
		}
	}
}

func (p *EndpointPolicy) RevertChanges(changes ChangeState) {
	p.policyMapState.revertChanges(changes)
}

// toMapState transforms an attached L4DirectionPolicy into
// the datapath-friendly format inside EndpointPolicy.PolicyMapState.
// Called with selectorcache locked for reading.
// Called without holding the Repository lock.
// PolicyOwner (aka Endpoint) is also unlocked during this call,
// but the Endpoint's build mutex is held.
func (l4policy L4DirectionPolicy) toMapState(logger *slog.Logger, p *EndpointPolicy) {
	for tier := range l4policy.PortRules {
		basePriority := l4policy.tierBasePriority[tier]
		nextTierPriority := types.MaxPriority
		if len(l4policy.tierBasePriority) > int(tier)+1 {
			nextTierPriority = l4policy.tierBasePriority[tier+1]
		}
		l4policy.PortRules[tier].ForEach(func(l4 *L4Filter) bool {
			l4.toMapState(logger, basePriority, nextTierPriority, p, l4policy.features, ChangeState{})
			return true
		})
	}
}

type PerSelectorPolicyTuple struct {
	Policy   *PerSelectorPolicy
	Selector CachedSelector
}

// RedirectFilters returns an iterator for each L4Filter with a redirect in the policy.
func (p *selectorPolicy) RedirectFilters() iter.Seq2[*L4Filter, PerSelectorPolicyTuple] {
	return func(yield func(*L4Filter, PerSelectorPolicyTuple) bool) {
		if p.L4Policy.Ingress.forEachRedirectFilter(yield) {
			p.L4Policy.Egress.forEachRedirectFilter(yield)
		}
	}
}

func (l4policy L4DirectionPolicy) forEachRedirectFilter(yield func(*L4Filter, PerSelectorPolicyTuple) bool) bool {
	ok := true
	for i := range l4policy.PortRules {
		l4policy.PortRules[i].ForEach(func(l4 *L4Filter) bool {
			for cs, ps := range l4.PerSelectorPolicies {
				if ps != nil && ps.IsRedirect() {
					if !yield(l4, PerSelectorPolicyTuple{ps, cs}) {
						ok = false
						return false
					}
				}
			}
			return true
		})
		if !ok {
			break
		}
	}
	return ok
}

// ConsumeMapChanges applies accumulated MapChanges to EndpointPolicy 'p' and returns a summary of
// changes.  Caller is responsible for calling the returned 'closer' to release resources held for
// the new revision!
func (p *EndpointPolicy) ConsumeMapChanges() (closer func(), changes ChangeState) {
	features := p.SelectorPolicy.L4Policy.Ingress.features | p.SelectorPolicy.L4Policy.Egress.features
	selectors, changes := p.policyMapChanges.consumeMapChanges(p, features)

	// Update current selector snapshot and provide a closer function to close the new snapshot
	// if (and only if) the old one was already closed.
	closer = func() {}
	if selectors.IsValid() {
		var msg string
		// update p.selectors so that any follow-on processing acts on the basis of the new
		// snapshot
		if p.selectors.IsValid() {
			p.selectors.Invalidate()
			msg = "ConsumeMapChanges: updated existing selector snapshot"
		} else {
			closer = func() {
				// p.selectors was not open, close the new one as well
				p.Ready()
			}
			msg = "ConsumeMapChanges: new incremental selector snapshot"
		}
		p.selectors = selectors

		p.PolicyOwner.PolicyDebug(msg,
			logfields.Version, selectors,
			logfields.Changes, changes,
		)
	}

	return closer, changes
}

// NewEndpointPolicy returns an empty EndpointPolicy stub.
// The returned stub is not modified.
func NewEndpointPolicy(logger *slog.Logger, repo PolicyRepository) *EndpointPolicy {
	return &EndpointPolicy{
		SelectorPolicy: newSelectorPolicy(repo.GetSelectorCache()),
		policyMapState: emptyMapState(logger),
	}
}
