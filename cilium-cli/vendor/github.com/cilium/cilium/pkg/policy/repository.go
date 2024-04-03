// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	cilium "github.com/cilium/proxy/go/cilium/api"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

// PolicyContext is an interface policy resolution functions use to access the Repository.
// This way testing code can run without mocking a full Repository.
type PolicyContext interface {
	// return the namespace in which the policy rule is being resolved
	GetNamespace() string

	// return the SelectorCache
	GetSelectorCache() *SelectorCache

	// GetTLSContext resolves the given 'api.TLSContext' into CA
	// certs and the public and private keys, using secrets from
	// k8s or from the local file system.
	GetTLSContext(tls *api.TLSContext) (ca, public, private string, err error)

	// GetEnvoyHTTPRules translates the given 'api.L7Rules' into
	// the protobuf representation the Envoy can consume. The bool
	// return parameter tells whether the rule enforcement can
	// be short-circuited upon the first allowing rule. This is
	// false if any of the rules has side-effects, requiring all
	// such rules being evaluated.
	GetEnvoyHTTPRules(l7Rules *api.L7Rules) (*cilium.HttpNetworkPolicyRules, bool)

	// IsDeny returns true if the policy computation should be done for the
	// policy deny case. This function returns different values depending on the
	// code path as it can be changed during the policy calculation.
	IsDeny() bool

	// SetDeny sets the Deny field of the PolicyContext and returns the old
	// value stored.
	SetDeny(newValue bool) (oldValue bool)
}

type policyContext struct {
	repo *Repository
	ns   string
	// isDeny this field is set to true if the given policy computation should
	// be done for the policy deny.
	isDeny bool
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
func (p *policyContext) GetTLSContext(tls *api.TLSContext) (ca, public, private string, err error) {
	if p.repo.certManager == nil {
		return "", "", "", fmt.Errorf("No Certificate Manager set on Policy Repository")
	}
	return p.repo.certManager.GetTLSContext(context.TODO(), tls, p.ns)
}

func (p *policyContext) GetEnvoyHTTPRules(l7Rules *api.L7Rules) (*cilium.HttpNetworkPolicyRules, bool) {
	return p.repo.GetEnvoyHTTPRules(l7Rules, p.ns)
}

// IsDeny returns true if the policy computation should be done for the
// policy deny case. This function return different values depending on the
// code path as it can be changed during the policy calculation.
func (p *policyContext) IsDeny() bool {
	return p.isDeny
}

// SetDeny sets the Deny field of the PolicyContext and returns the old
// value stored.
func (p *policyContext) SetDeny(deny bool) bool {
	oldDeny := p.isDeny
	p.isDeny = deny
	return oldDeny
}

// Repository is a list of policy rules which in combination form the security
// policy. A policy repository can be
type Repository struct {
	// Mutex protects the whole policy tree
	Mutex lock.RWMutex
	rules ruleSlice

	// rulesIndexByK8sUID indexes the rules by k8s UID.
	rulesIndexByK8sUID map[string]*rule

	// revision is the revision of the policy repository. It will be
	// incremented whenever the policy repository is changed.
	// Always positive (>0).
	revision atomic.Uint64

	// RepositoryChangeQueue is a queue which serializes changes to the policy
	// repository.
	RepositoryChangeQueue *eventqueue.EventQueue

	// RuleReactionQueue is a queue which serializes the resultant events that
	// need to occur after updating the state of the policy repository. This
	// can include queueing endpoint regenerations, policy revision increments
	// for endpoints, etc.
	RuleReactionQueue *eventqueue.EventQueue

	// SelectorCache tracks the selectors used in the policies
	// resolved from the repository.
	selectorCache *SelectorCache

	// PolicyCache tracks the selector policies created from this repo
	policyCache *PolicyCache

	certManager   certificatemanager.CertificateManager
	secretManager certificatemanager.SecretManager

	getEnvoyHTTPRules func(certificatemanager.SecretManager, *api.L7Rules, string) (*cilium.HttpNetworkPolicyRules, bool)
}

// GetSelectorCache() returns the selector cache used by the Repository
func (p *Repository) GetSelectorCache() *SelectorCache {
	return p.selectorCache
}

// GetAuthTypes returns the AuthTypes required by the policy between the localID and remoteID
func (p *Repository) GetAuthTypes(localID, remoteID identity.NumericIdentity) AuthTypes {
	return p.policyCache.GetAuthTypes(localID, remoteID)
}

func (p *Repository) SetEnvoyRulesFunc(f func(certificatemanager.SecretManager, *api.L7Rules, string) (*cilium.HttpNetworkPolicyRules, bool)) {
	p.getEnvoyHTTPRules = f
}

func (p *Repository) GetEnvoyHTTPRules(l7Rules *api.L7Rules, ns string) (*cilium.HttpNetworkPolicyRules, bool) {
	if p.getEnvoyHTTPRules == nil {
		return nil, true
	}
	return p.getEnvoyHTTPRules(p.secretManager, l7Rules, ns)
}

// GetPolicyCache() returns the policy cache used by the Repository
func (p *Repository) GetPolicyCache() *PolicyCache {
	return p.policyCache
}

// NewPolicyRepository creates a new policy repository.
func NewPolicyRepository(
	idAllocator cache.IdentityAllocator,
	idCache cache.IdentityCache,
	certManager certificatemanager.CertificateManager,
	secretManager certificatemanager.SecretManager,
) *Repository {
	repo := NewStoppedPolicyRepository(idAllocator, idCache, certManager, secretManager)
	repo.Start()
	return repo
}

// NewStoppedPolicyRepository creates a new policy repository without starting
// queues.
//
// Qeues must be allocated via [Repository.Start]. The function serves to
// satisfy hive invariants.
func NewStoppedPolicyRepository(
	idAllocator cache.IdentityAllocator,
	idCache cache.IdentityCache,
	certManager certificatemanager.CertificateManager,
	secretManager certificatemanager.SecretManager,
) *Repository {
	selectorCache := NewSelectorCache(idAllocator, idCache)
	repo := &Repository{
		rulesIndexByK8sUID: map[string]*rule{},
		selectorCache:      selectorCache,
		certManager:        certManager,
		secretManager:      secretManager,
	}
	repo.revision.Store(1)
	repo.policyCache = NewPolicyCache(repo, true)
	return repo
}

// traceState is an internal structure used to collect information
// while determining policy decision
type traceState struct {
	// selectedRules is the number of rules with matching EndpointSelector
	selectedRules int

	// matchedRules is the number of rules that have allowed traffic
	matchedRules int

	// matchedDenyRules is the number of rules that have denied traffic
	matchedDenyRules int

	// constrainedRules counts how many "FromRequires" constraints are
	// unsatisfied
	constrainedRules int

	// ruleID is the rule ID currently being evaluated
	ruleID int
}

func (state *traceState) trace(rules int, ctx *SearchContext) {
	ctx.PolicyTrace("%d/%d rules selected\n", state.selectedRules, rules)
	if state.constrainedRules > 0 {
		ctx.PolicyTrace("Found unsatisfied FromRequires constraint\n")
	} else {
		if state.matchedRules > 0 {
			ctx.PolicyTrace("Found allow rule\n")
		} else {
			ctx.PolicyTrace("Found no allow rule\n")
		}
		if state.matchedDenyRules > 0 {
			ctx.PolicyTrace("Found deny rule\n")
		} else {
			ctx.PolicyTrace("Found no deny rule\n")
		}
	}
}

// Start allocates and starts various queues used by the Repository.
//
// Must only be called if using [NewStoppedPolicyRepository]
func (p *Repository) Start() {
	p.RepositoryChangeQueue = eventqueue.NewEventQueueBuffered("repository-change-queue", option.Config.PolicyQueueSize)
	p.RuleReactionQueue = eventqueue.NewEventQueueBuffered("repository-reaction-queue", option.Config.PolicyQueueSize)
	p.RepositoryChangeQueue.Run()
	p.RuleReactionQueue.Run()
}

// ResolveL4IngressPolicy resolves the L4 ingress policy for a set of endpoints
// by searching the policy repository for `PortRule` rules that are attached to
// a `Rule` where the EndpointSelector matches `ctx.To`. `ctx.From` takes no effect and
// is ignored in the search.  If multiple `PortRule` rules are found, all rules
// are merged together. If rules contains overlapping port definitions, the first
// rule found in the repository takes precedence.
//
// TODO: Coalesce l7 rules?
//
// Caller must release resources by calling Detach() on the returned map!
//
// NOTE: This is only called from unit tests, but from multiple packages.
func (p *Repository) ResolveL4IngressPolicy(ctx *SearchContext) (L4PolicyMap, error) {
	policyCtx := policyContext{
		repo: p,
		ns:   ctx.To.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel),
	}
	result, err := p.rules.resolveL4IngressPolicy(&policyCtx, ctx)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// ResolveL4EgressPolicy resolves the L4 egress policy for a set of endpoints
// by searching the policy repository for `PortRule` rules that are attached to
// a `Rule` where the EndpointSelector matches `ctx.From`. `ctx.To` takes no effect and
// is ignored in the search.  If multiple `PortRule` rules are found, all rules
// are merged together. If rules contains overlapping port definitions, the first
// rule found in the repository takes precedence.
//
// Caller must release resources by calling Detach() on the returned map!
//
// NOTE: This is only called from unit tests, but from multiple packages.
func (p *Repository) ResolveL4EgressPolicy(ctx *SearchContext) (L4PolicyMap, error) {
	policyCtx := policyContext{
		repo: p,
		ns:   ctx.From.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel),
	}
	result, err := p.rules.resolveL4EgressPolicy(&policyCtx, ctx)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// AllowsIngressRLocked evaluates the policy repository for the provided search
// context and returns the verdict for ingress. If no matching policy allows for
// the  connection, the request will be denied. The policy repository mutex must
// be held.
//
// NOTE: This is only called from unit tests, but from multiple packages.
func (p *Repository) AllowsIngressRLocked(ctx *SearchContext) api.Decision {
	// Lack of DPorts in the SearchContext means L3-only search
	if len(ctx.DPorts) == 0 {
		newCtx := *ctx
		newCtx.DPorts = []*models.Port{{
			Port:     0,
			Protocol: models.PortProtocolANY,
		}}
		ctx = &newCtx
	}

	ctx.PolicyTrace("Tracing %s", ctx.String())
	ingressPolicy, err := p.ResolveL4IngressPolicy(ctx)
	if err != nil {
		log.WithError(err).Warn("Evaluation error while resolving L4 ingress policy")
	}

	verdict := api.Denied
	if err == nil && len(ingressPolicy) > 0 {
		verdict = ingressPolicy.IngressCoversContext(ctx)
	}

	ctx.PolicyTrace("Ingress verdict: %s", verdict.String())
	ingressPolicy.Detach(p.GetSelectorCache())

	return verdict
}

// AllowsEgressRLocked evaluates the policy repository for the provided search
// context and returns the verdict. If no matching policy allows for the
// connection, the request will be denied. The policy repository mutex must be
// held.
//
// NOTE: This is only called from unit tests, but from multiple packages.
func (p *Repository) AllowsEgressRLocked(ctx *SearchContext) api.Decision {
	// Lack of DPorts in the SearchContext means L3-only search
	if len(ctx.DPorts) == 0 {
		newCtx := *ctx
		newCtx.DPorts = []*models.Port{{
			Port:     0,
			Protocol: models.PortProtocolANY,
		}}
		ctx = &newCtx
	}

	ctx.PolicyTrace("Tracing %s\n", ctx.String())
	egressPolicy, err := p.ResolveL4EgressPolicy(ctx)
	if err != nil {
		log.WithError(err).Warn("Evaluation error while resolving L4 egress policy")
	}
	verdict := api.Denied
	if err == nil && len(egressPolicy) > 0 {
		verdict = egressPolicy.EgressCoversContext(ctx)
	}

	ctx.PolicyTrace("Egress verdict: %s", verdict.String())
	egressPolicy.Detach(p.GetSelectorCache())
	return verdict
}

// SearchRLocked searches the policy repository for rules which match the
// specified labels and will return an array of all rules which matched.
func (p *Repository) SearchRLocked(lbls labels.LabelArray) api.Rules {
	result := api.Rules{}

	if uid := lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PolicyLabelUID); uid != "" {
		r, ok := p.rulesIndexByK8sUID[uid]
		if ok {
			result = append(result, &r.Rule)
		}
		return result
	}
	for _, r := range p.rules {
		if r.Labels.Contains(lbls) {
			result = append(result, &r.Rule)
		}
	}

	return result
}

// Add inserts a rule into the policy repository
// This is just a helper function for unit testing.
// TODO: this should be in a test_helpers.go file or something similar
// so we can clearly delineate what helpers are for testing.
// NOTE: This is only called from unit tests, but from multiple packages.
func (p *Repository) Add(r api.Rule) (uint64, map[uint16]struct{}, error) {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()

	if err := r.Sanitize(); err != nil {
		return p.GetRevision(), nil, err
	}

	newList := make([]*api.Rule, 1)
	newList[0] = &r
	_, rev := p.AddListLocked(newList)
	return rev, map[uint16]struct{}{}, nil
}

// AddListLocked inserts a rule into the policy repository with the repository already locked
// Expects that the entire rule list has already been sanitized.
func (p *Repository) AddListLocked(rules api.Rules) (ruleSlice, uint64) {

	newList := make(ruleSlice, len(rules))
	for i := range rules {
		newRule := &rule{
			Rule:     *rules[i],
			metadata: newRuleMetadata(),
		}
		newList[i] = newRule
		if uid := rules[i].Labels.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PolicyLabelUID); uid != "" {
			p.rulesIndexByK8sUID[uid] = newRule
		}
	}

	p.rules = append(p.rules, newList...)
	p.BumpRevision()
	metrics.Policy.Add(float64(len(newList)))
	return newList, p.GetRevision()
}

// removeIdentityFromRuleCaches removes the identity from the selector cache
// in each rule in the repository.
//
// Returns a sync.WaitGroup that blocks until the policy operation is complete.
// The repository read lock must be held until the waitgroup is complete.
func (p *Repository) removeIdentityFromRuleCaches(identity *identity.Identity) *sync.WaitGroup {
	var wg sync.WaitGroup
	wg.Add(len(p.rules))
	for _, r := range p.rules {
		go func(rr *rule, wgg *sync.WaitGroup) {
			rr.metadata.delete(identity)
			wgg.Done()
		}(r, &wg)
	}
	return &wg
}

// LocalEndpointIdentityAdded handles local identity add events.
func (p *Repository) LocalEndpointIdentityAdded(*identity.Identity) {
	// no-op for now.
}

// LocalEndpointIdentityRemoved handles local identity removal events to
// remove references from rules in the repository to the specified identity.
func (p *Repository) LocalEndpointIdentityRemoved(identity *identity.Identity) {
	go func() {
		scopedLog := log.WithField(logfields.Identity, identity)
		scopedLog.Debug("Removing identity references from policy cache")
		p.Mutex.RLock()
		wg := p.removeIdentityFromRuleCaches(identity)
		wg.Wait()
		p.Mutex.RUnlock()
		scopedLog.Debug("Finished cleaning policy cache")
	}()
}

// AddList inserts a rule into the policy repository. It is used for
// unit-testing purposes only.
func (p *Repository) AddList(rules api.Rules) (ruleSlice, uint64) {
	for i := range rules {
		// FIXME(GH-31162): Many unit tests provide invalid rules
		_ = rules[i].Sanitize()
	}
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	return p.AddListLocked(rules)
}

// Iterate iterates the policy repository, calling f for each rule. It is safe
// to execute Iterate concurrently.
func (p *Repository) Iterate(f func(rule *api.Rule)) {
	p.Mutex.RWMutex.Lock()
	defer p.Mutex.RWMutex.Unlock()
	for _, r := range p.rules {
		f(&r.Rule)
	}
}

// UpdateRulesEndpointsCaches updates the caches within each rule in r that
// specify whether the rule selects the endpoints in eps. If any rule matches
// the endpoints, it is added to the provided IDSet, and removed from the
// provided EndpointSet. The provided WaitGroup is signaled for a given endpoint
// when it is finished being processed.
func (r ruleSlice) UpdateRulesEndpointsCaches(endpointsToBumpRevision, endpointsToRegenerate *EndpointSet, policySelectionWG *sync.WaitGroup) {
	endpointsToBumpRevision.ForEachGo(policySelectionWG, func(epp Endpoint) {
		endpointSelected, err := r.updateEndpointsCaches(epp)
		if endpointSelected {
			endpointsToRegenerate.Insert(epp)
		}
		// If we could not evaluate the rules against the current endpoint, or
		// the endpoint is selected by the rules, remove it from the set of
		// endpoints to bump the revision. If the error is non-nil, the
		// endpoint is no longer in either set (endpointsToBumpRevision or
		// endpointsToRegenerate, as we could not determine what to do for the
		// endpoint). This is usually the case when the endpoint is no longer
		// alive (i.e., it has been marked to be deleted).
		if endpointSelected || err != nil {
			if err != nil {
				log.WithError(err).Debug("could not determine whether endpoint was selected by rule")
			}
			endpointsToBumpRevision.Delete(epp)
		}
	})
}

// DeleteByLabelsLocked deletes all rules in the policy repository which
// contain the specified labels. Returns the revision of the policy repository
// after deleting the rules, as well as now many rules were deleted.
func (p *Repository) DeleteByLabelsLocked(lbls labels.LabelArray) (ruleSlice, uint64, int) {

	deleted := 0
	new := p.rules[:0]
	deletedRules := ruleSlice{}

	for _, r := range p.rules {
		if !r.Labels.Contains(lbls) {
			new = append(new, r)
		} else {
			deletedRules = append(deletedRules, r)
			deleted++
		}
	}

	if deleted > 0 {
		p.BumpRevision()
		p.rules = new
		if uid := lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PolicyLabelUID); uid != "" {
			delete(p.rulesIndexByK8sUID, uid)
		}
		metrics.Policy.Sub(float64(deleted))
	}

	return deletedRules, p.GetRevision(), deleted
}

// DeleteByLabels deletes all rules in the policy repository which contain the
// specified labels
func (p *Repository) DeleteByLabels(lbls labels.LabelArray) (uint64, int) {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	_, rev, numDeleted := p.DeleteByLabelsLocked(lbls)
	return rev, numDeleted
}

// JSONMarshalRules returns a slice of policy rules as string in JSON
// representation
func JSONMarshalRules(rules api.Rules) string {
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// GetJSON returns all rules of the policy repository as string in JSON
// representation
func (p *Repository) GetJSON() string {
	p.Mutex.RLock()
	defer p.Mutex.RUnlock()

	result := api.Rules{}
	for _, r := range p.rules {
		result = append(result, &r.Rule)
	}

	return JSONMarshalRules(result)
}

// GetRulesMatching returns whether any of the rules in a repository contain a
// rule with labels matching the labels in the provided LabelArray.
//
// Must be called with p.Mutex held
func (p *Repository) GetRulesMatching(lbls labels.LabelArray) (ingressMatch bool, egressMatch bool) {
	ingressMatch = false
	egressMatch = false
	for _, r := range p.rules {
		rulesMatch := r.getSelector().Matches(lbls)
		if rulesMatch {
			if len(r.Ingress) > 0 {
				ingressMatch = true
			}
			if len(r.IngressDeny) > 0 {
				ingressMatch = true
			}
			if len(r.Egress) > 0 {
				egressMatch = true
			}
			if len(r.EgressDeny) > 0 {
				egressMatch = true
			}
		}

		if ingressMatch && egressMatch {
			return
		}
	}
	return
}

// NumRules returns the amount of rules in the policy repository.
//
// Must be called with p.Mutex held
func (p *Repository) NumRules() int {
	return len(p.rules)
}

// GetRevision returns the revision of the policy repository
func (p *Repository) GetRevision() uint64 {
	return p.revision.Load()
}

// Empty returns 'true' if repository has no rules, 'false' otherwise.
//
// Must be called without p.Mutex held
func (p *Repository) Empty() bool {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	return p.NumRules() == 0
}

// BumpRevision allows forcing policy regeneration
func (p *Repository) BumpRevision() {
	metrics.PolicyRevision.Inc()
	p.revision.Add(1)
}

// GetRulesList returns the current policy
func (p *Repository) GetRulesList() *models.Policy {
	p.Mutex.RLock()
	defer p.Mutex.RUnlock()

	lbls := labels.ParseSelectLabelArrayFromArray([]string{})
	ruleList := p.SearchRLocked(lbls)

	return &models.Policy{
		Revision: int64(p.GetRevision()),
		Policy:   JSONMarshalRules(ruleList),
	}
}

// resolvePolicyLocked returns the selectorPolicy for the provided
// identity from the set of rules in the repository.  If the policy
// cannot be generated due to conflicts at L4 or L7, returns an error.
//
// Must be performed while holding the Repository lock.
func (p *Repository) resolvePolicyLocked(securityIdentity *identity.Identity) (*selectorPolicy, error) {
	// First obtain whether policy applies in both traffic directions, as well
	// as list of rules which actually select this endpoint. This allows us
	// to not have to iterate through the entire rule list multiple times and
	// perform the matching decision again when computing policy for each
	// protocol layer, which is quite costly in terms of performance.
	ingressEnabled, egressEnabled,
		matchingRules :=
		p.computePolicyEnforcementAndRules(securityIdentity)

	calculatedPolicy := &selectorPolicy{
		Revision:             p.GetRevision(),
		SelectorCache:        p.GetSelectorCache(),
		L4Policy:             NewL4Policy(p.GetRevision()),
		IngressPolicyEnabled: ingressEnabled,
		EgressPolicyEnabled:  egressEnabled,
	}

	lbls := securityIdentity.LabelArray
	ingressCtx := SearchContext{
		To:          lbls,
		rulesSelect: true,
	}

	egressCtx := SearchContext{
		From:        lbls,
		rulesSelect: true,
	}

	if option.Config.TracingEnabled() {
		ingressCtx.Trace = TRACE_ENABLED
		egressCtx.Trace = TRACE_ENABLED
	}

	policyCtx := policyContext{
		repo: p,
		ns:   lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel),
	}

	if ingressEnabled {
		newL4IngressPolicy, err := matchingRules.resolveL4IngressPolicy(&policyCtx, &ingressCtx)
		if err != nil {
			return nil, err
		}
		calculatedPolicy.L4Policy.Ingress.PortRules = newL4IngressPolicy
	}

	if egressEnabled {
		newL4EgressPolicy, err := matchingRules.resolveL4EgressPolicy(&policyCtx, &egressCtx)
		if err != nil {
			return nil, err
		}
		calculatedPolicy.L4Policy.Egress.PortRules = newL4EgressPolicy
	}

	// Make the calculated policy ready for incremental updates
	calculatedPolicy.Attach(&policyCtx)

	return calculatedPolicy, nil
}

// computePolicyEnforcementAndRules returns whether policy applies at ingress or ingress
// for the given security identity, as well as a list of any rules which select
// the set of labels of the given security identity.
//
// Must be called with repo mutex held for reading.
func (p *Repository) computePolicyEnforcementAndRules(securityIdentity *identity.Identity) (
	ingress, egress bool,
	matchingRules ruleSlice,
) {
	lbls := securityIdentity.LabelArray

	// Check if policy enforcement should be enabled at the daemon level.
	if lbls.Has(labels.IDNameHost) && !option.Config.EnableHostFirewall {
		return false, false, nil
	}

	policyMode := GetPolicyEnabled()
	// If policy enforcement isn't enabled, we do not enable policy
	// enforcement for the endpoint. We don't care about returning any
	// rules that match.
	if policyMode == option.NeverEnforce {
		return false, false, nil
	}

	matchingRules = []*rule{}
	for _, r := range p.rules {
		if r.matches(securityIdentity) {
			matchingRules = append(matchingRules, r)
		}
	}

	// If policy enforcement is enabled for the daemon, then it has to be
	// enabled for the endpoint.
	// If the endpoint has the reserved:init label, i.e. if it has not yet
	// received any labels, always enforce policy (default deny).
	if policyMode == option.AlwaysEnforce || lbls.Has(labels.IDNameInit) {
		return true, true, matchingRules
	}

	// Determine the default policy for each direction.
	//
	// By default, endpoints have no policy and all traffic is allowed.
	// If any rules select the endpoint, then the endpoint switches to a
	// default-deny mode (same as traffic being enabled), per-direction.
	//
	// Rules, however, can optionally be configure to not enable default deny mode.
	// If no rules enable default-deny, then all traffic is allowed except that explicitly
	// denied by a Deny rule.
	//
	// There are three possible cases _per direction_:
	// 1: No rules are present,
	// 2: At least one default-deny rule is present. Then, policy is enabled
	// 3: Only non-default-deny rules are present. Then, policy is enabled, but we must insert
	//    an additional allow-all rule. We must do this, even if all traffic is allowed, because
	//    rules may have additional effects such as enabling L7 proxy.
	hasIngressDefaultDeny := false
	hasEgressDefaultDeny := false
	for _, r := range matchingRules {
		if !ingress || !hasIngressDefaultDeny { // short-circuit len()
			if len(r.Ingress) > 0 || len(r.IngressDeny) > 0 {
				ingress = true
				if *r.EnableDefaultDeny.Ingress {
					hasIngressDefaultDeny = true
				}
			}
		}

		if !egress || !hasEgressDefaultDeny { // short-circuit len()
			if len(r.Egress) > 0 || len(r.EgressDeny) > 0 {
				egress = true
				if *r.EnableDefaultDeny.Egress {
					hasEgressDefaultDeny = true
				}
			}
		}
		if ingress && egress && hasIngressDefaultDeny && hasEgressDefaultDeny {
			break
		}
	}

	// If there only ingress default-allow rules, then insert a wildcard rule
	if !hasIngressDefaultDeny && ingress {
		log.WithField(logfields.Identity, securityIdentity).Info("Only default-allow policies, synthesizing ingress wildcard-allow rule")
		matchingRules = append(matchingRules, wildcardRule(securityIdentity.LabelArray, true /*ingress*/))
	}

	// Same for egress -- synthesize a wildcard rule
	if !hasEgressDefaultDeny && egress {
		log.WithField(logfields.Identity, securityIdentity).Info("Only default-allow policies, synthesizing egress wildcard-allow rule")
		matchingRules = append(matchingRules, wildcardRule(securityIdentity.LabelArray, false /*egress*/))
	}

	return
}

// wildcardRule generates a wildcard rule that only selects the given identity.
func wildcardRule(lbls labels.LabelArray, ingress bool) *rule {
	r := &rule{
		metadata: newRuleMetadata(),
	}

	if ingress {
		r.Ingress = []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEntities: []api.Entity{api.EntityAll},
				},
			},
		}
	} else {
		r.Egress = []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEntities: []api.Entity{api.EntityAll},
				},
			},
		}
	}

	es := api.NewESFromLabels(lbls...)
	if lbls.Has(labels.IDNameHost) {
		r.NodeSelector = es
	} else {
		r.EndpointSelector = es
	}
	_ = r.Sanitize()

	return r
}
