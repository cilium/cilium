// Copyright 2016-2019 Authors of Cilium
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
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Repository is a list of policy rules which in combination form the security
// policy. A policy repository can be
type Repository struct {
	// Mutex protects the whole policy tree
	Mutex lock.RWMutex
	rules ruleSlice

	// revision is the revision of the policy repository. It will be
	// incremented whenever the policy repository is changed.
	// Always positive (>0).
	revision uint64

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
	SelectorCache *SelectorCache
}

// NewPolicyRepository allocates a new policy repository
func NewPolicyRepository() *Repository {
	repoChangeQueue := eventqueue.NewEventQueueBuffered("repository-change-queue", option.Config.PolicyQueueSize)
	ruleReactionQueue := eventqueue.NewEventQueueBuffered("repository-reaction-queue", option.Config.PolicyQueueSize)
	repoChangeQueue.Run()
	ruleReactionQueue.Run()
	return &Repository{
		revision:              1,
		RepositoryChangeQueue: repoChangeQueue,
		RuleReactionQueue:     ruleReactionQueue,
		SelectorCache:         NewSelectorCache(cache.GetIdentityCache()),
	}
}

// traceState is an internal structure used to collect information
// while determining policy decision
type traceState struct {
	// selectedRules is the number of rules with matching EndpointSelector
	selectedRules int

	// matchedRules is the number of rules that have allowed traffic
	matchedRules int

	// constrainedRules counts how many "FromRequires" constraints are
	// unsatisfied
	constrainedRules int

	// ruleID is the rule ID currently being evaluated
	ruleID int
}

func (state *traceState) trace(rules ruleSlice, ctx *SearchContext) {
	ctx.PolicyTrace("%d/%d rules selected\n", state.selectedRules, len(rules))
	if state.constrainedRules > 0 {
		ctx.PolicyTrace("Found unsatisfied FromRequires constraint\n")
	} else if state.matchedRules > 0 {
		ctx.PolicyTrace("Found allow rule\n")
	} else {
		ctx.PolicyTrace("Found no allow rule\n")
	}
}

// This belongs to l4.go as this manipulates L4Filters
func wildcardL3L4Rule(proto api.L4Proto, port int, endpoints api.EndpointSelectorSlice,
	ruleLabels labels.LabelArray, l4Policy L4PolicyMap, selectorCache *SelectorCache) {
	for _, filter := range l4Policy {
		if proto != filter.Protocol || (port != 0 && port != filter.Port) {
			continue
		}
		switch filter.L7Parser {
		case ParserTypeNone:
			continue
		case ParserTypeHTTP:
			// Wildcard at L7 all the endpoints allowed at L3 or L4.
			for _, sel := range endpoints {
				cs := filter.cacheIdentitySelector(sel, selectorCache)
				filter.L7RulesPerEp[cs] = api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				}
			}
		case ParserTypeKafka:
			// Wildcard at L7 all the endpoints allowed at L3 or L4.
			for _, sel := range endpoints {
				rule := api.PortRuleKafka{}
				rule.Sanitize()
				cs := filter.cacheIdentitySelector(sel, selectorCache)
				filter.L7RulesPerEp[cs] = api.L7Rules{
					Kafka: []api.PortRuleKafka{rule},
				}
			}
		case ParserTypeDNS:
			// Wildcard at L7 all the endpoints allowed at L3 or L4.
			for _, sel := range endpoints {
				rule := api.PortRuleDNS{}
				rule.Sanitize()
				cs := filter.cacheIdentitySelector(sel, selectorCache)
				filter.L7RulesPerEp[cs] = api.L7Rules{
					DNS: []api.PortRuleDNS{rule},
				}
			}
		default:
			// Wildcard at L7 all the endpoints allowed at L3 or L4.
			for _, sel := range endpoints {
				cs := filter.cacheIdentitySelector(sel, selectorCache)
				filter.L7RulesPerEp[cs] = api.L7Rules{
					L7Proto: filter.L7Parser.String(),
					L7:      []api.PortRuleL7{},
				}
			}
		}
		filter.DerivedFromRules = append(filter.DerivedFromRules, ruleLabels)
		// l4Policy[k] = filter // pointer now, no need to reset
	}
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
// Caller must release resources by calling Delete() on the returned map!
//
// Note: Only used for policy tracing
func (p *Repository) ResolveL4IngressPolicy(ctx *SearchContext) (*L4PolicyMap, error) {

	result, err := p.rules.resolveL4IngressPolicy(ctx, p.GetRevision(), p.SelectorCache)
	if err != nil {
		return nil, err
	}

	return &result.Ingress, nil
}

// ResolveL4EgressPolicy resolves the L4 egress policy for a set of endpoints
// by searching the policy repository for `PortRule` rules that are attached to
// a `Rule` where the EndpointSelector matches `ctx.From`. `ctx.To` takes no effect and
// is ignored in the search.  If multiple `PortRule` rules are found, all rules
// are merged together. If rules contains overlapping port definitions, the first
// rule found in the repository takes precedence.
//
// Caller must release resources by calling Delete() on the returned map!
//
// NOTE: This is only called from unit tests.
func (p *Repository) ResolveL4EgressPolicy(ctx *SearchContext) (*L4PolicyMap, error) {
	result, err := p.rules.resolveL4EgressPolicy(ctx, p.GetRevision(), p.SelectorCache)

	if err != nil {
		return nil, err
	}

	return &result.Egress, nil
}

// AllowsIngressRLocked evaluates the policy repository for the provided search
// context and returns the verdict for ingress. If no matching policy allows for
// the  connection, the request will be denied. The policy repository mutex must
// be held.
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
	if err == nil && len(*ingressPolicy) > 0 {
		verdict = ingressPolicy.IngressCoversContext(ctx)
	}

	ctx.PolicyTrace("Ingress verdict: %s", verdict.String())
	ingressPolicy.Delete(p.SelectorCache)

	return verdict
}

// AllowsEgressRLocked evaluates the policy repository for the provided search
// context and returns the verdict. If no matching policy allows for the
// connection, the request will be denied. The policy repository mutex must be
// held.
//
// NOTE: This is only called from unit tests.
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
	if err == nil && len(*egressPolicy) > 0 {
		verdict = egressPolicy.EgressCoversContext(ctx)
	}

	ctx.PolicyTrace("Egress verdict: %s", verdict.String())
	egressPolicy.Delete(p.SelectorCache)
	return verdict
}

// SearchRLocked searches the policy repository for rules which match the
// specified labels and will return an array of all rules which matched.
func (p *Repository) SearchRLocked(labels labels.LabelArray) api.Rules {
	result := api.Rules{}

	for _, r := range p.rules {
		if r.Labels.Contains(labels) {
			result = append(result, &r.Rule)
		}
	}

	return result
}

// Add inserts a rule into the policy repository
// This is just a helper function for unit testing.
// TODO: this should be in a test_helpers.go file or something similar
// so we can clearly delineate what helpers are for testing.
func (p *Repository) Add(r api.Rule, localRuleConsumers []Endpoint) (uint64, map[uint16]struct{}, error) {
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
	}

	p.rules = append(p.rules, newList...)
	p.BumpRevision()
	metrics.PolicyCount.Add(float64(len(newList)))

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
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	return p.AddListLocked(rules)
}

// UpdateRulesEndpointsCaches updates the caches within each rule in r that
// specify whether the rule selects the endpoints in eps. If any rule matches
// the endpoints, it is added to the provided IDSet, and removed from the
// provided EndpointSet. The provided WaitGroup is signaled for a given endpoint
// when it is finished being processed.
func (r ruleSlice) UpdateRulesEndpointsCaches(endpointsToBumpRevision *EndpointSet, endpointsToRegenerate *IDSet, policySelectionWG *sync.WaitGroup) {
	// No need to check whether endpoints need to be regenerated here since we
	// will unconditionally regenerate all endpoints later.
	if !option.Config.SelectiveRegeneration {
		return
	}

	endpointsToBumpRevision.ForEach(policySelectionWG, func(epp Endpoint) {
		endpointSelected, err := r.updateEndpointsCaches(epp, endpointsToRegenerate)

		// If we could not evaluate the rules against the current endpoint, or
		// the endpoint is not selected by the rules, remove it from the set
		// of endpoints to bump the revision. If the error is non-nil, the
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
func (p *Repository) DeleteByLabelsLocked(labels labels.LabelArray) (ruleSlice, uint64, int) {

	deleted := 0
	new := p.rules[:0]
	deletedRules := ruleSlice{}

	for _, r := range p.rules {
		if !r.Labels.Contains(labels) {
			new = append(new, r)
		} else {
			deletedRules = append(deletedRules, r)
			deleted++
		}
	}

	if deleted > 0 {
		p.BumpRevision()
		p.rules = new
		metrics.PolicyCount.Sub(float64(deleted))
	}

	return deletedRules, p.GetRevision(), deleted
}

// DeleteByLabels deletes all rules in the policy repository which contain the
// specified labels
func (p *Repository) DeleteByLabels(labels labels.LabelArray) (uint64, int) {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	_, rev, numDeleted := p.DeleteByLabelsLocked(labels)
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
func (p *Repository) GetRulesMatching(labels labels.LabelArray) (ingressMatch bool, egressMatch bool) {
	ingressMatch = false
	egressMatch = false
	for _, r := range p.rules {
		rulesMatch := r.EndpointSelector.Matches(labels)
		if rulesMatch {
			if len(r.Ingress) > 0 {
				ingressMatch = true
			}
			if len(r.Egress) > 0 {
				egressMatch = true
			}
		}

		if ingressMatch && egressMatch {
			return
		}
	}
	return
}

// getMatchingRules returns whether any of the rules in a repository contain a
// rule with labels matching the given security identity, as well as
// a slice of all rules which match.
//
// Must be called with p.Mutex held
func (p *Repository) getMatchingRules(securityIdentity *identity.Identity) (ingressMatch bool, egressMatch bool, matchingRules ruleSlice) {
	matchingRules = []*rule{}
	ingressMatch = false
	egressMatch = false
	for _, r := range p.rules {
		if ruleMatches := r.matches(securityIdentity); ruleMatches {
			// Don't need to update whether ingressMatch is true if it already
			// has been determined to be true - allows us to not have to check
			// lenth of slice.
			if !ingressMatch && len(r.Ingress) > 0 {
				ingressMatch = true
			}
			if !egressMatch && len(r.Egress) > 0 {
				egressMatch = true
			}
			matchingRules = append(matchingRules, r)
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
	return atomic.LoadUint64(&p.revision)
}

// Empty returns 'true' if repository has no rules, 'false' otherwise.
//
// Must be called without p.Mutex held
func (p *Repository) Empty() bool {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	return p.NumRules() == 0
}

// TranslationResult contains the results of the rule translation
type TranslationResult struct {
	// NumToServicesRules is the number of ToServices rules processed while
	// translating the rules
	NumToServicesRules int
}

// TranslateRules traverses rules and applies provided translator to rules
//
// Note: Only used by the k8s watcher.
func (p *Repository) TranslateRules(translator Translator) (*TranslationResult, error) {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()

	result := &TranslationResult{}

	for ruleIndex := range p.rules {
		if err := translator.Translate(&p.rules[ruleIndex].Rule, result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// BumpRevision allows forcing policy regeneration
func (p *Repository) BumpRevision() {
	metrics.PolicyRevision.Inc()
	atomic.AddUint64(&p.revision, 1)
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

// ResolvePolicyLocked returns the SelectorPolicy for the provided
// identity from the set of rules in the repository.  If the policy
// cannot be generated due to conflicts at L4 or L7, returns an error.
//
// Must be performed while holding the Repository lock.
func (p *Repository) ResolvePolicyLocked(securityIdentity *identity.Identity) (*SelectorPolicy, error) {
	// First obtain whether policy applies in both traffic directions, as well
	// as list of rules which actually select this endpoint. This allows us
	// to not have to iterate through the entire rule list multiple times and
	// perform the matching decision again when computing policy for each
	// protocol layer, which is quite costly in terms of performance.
	ingressEnabled, egressEnabled, matchingRules := p.computePolicyEnforcementAndRules(securityIdentity)

	calculatedPolicy := &SelectorPolicy{
		Revision:             p.GetRevision(),
		L4Policy:             NewL4Policy(),
		CIDRPolicy:           NewCIDRPolicy(),
		IngressPolicyEnabled: ingressEnabled,
		EgressPolicyEnabled:  egressEnabled,
	}
	calculatedPolicy.IngressPolicyEnabled = ingressEnabled
	calculatedPolicy.EgressPolicyEnabled = egressEnabled

	labels := securityIdentity.LabelArray
	ingressCtx := SearchContext{
		To:          labels,
		rulesSelect: true,
	}

	egressCtx := SearchContext{
		From:        labels,
		rulesSelect: true,
	}

	if option.Config.TracingEnabled() {
		ingressCtx.Trace = TRACE_ENABLED
		egressCtx.Trace = TRACE_ENABLED
	}

	if ingressEnabled {
		newL4IngressPolicy, err := matchingRules.resolveL4IngressPolicy(&ingressCtx, p.GetRevision(), p.SelectorCache)
		if err != nil {
			return nil, err
		}

		newCIDRIngressPolicy := matchingRules.resolveCIDRPolicy(&ingressCtx)
		if err := newCIDRIngressPolicy.Validate(); err != nil {
			return nil, err
		}

		calculatedPolicy.CIDRPolicy.Ingress = newCIDRIngressPolicy.Ingress
		calculatedPolicy.L4Policy.Ingress = newL4IngressPolicy.Ingress
	}

	if egressEnabled {
		newL4EgressPolicy, err := matchingRules.resolveL4EgressPolicy(&egressCtx, p.GetRevision(), p.SelectorCache)
		if err != nil {
			return nil, err
		}

		newCIDREgressPolicy := matchingRules.resolveCIDRPolicy(&egressCtx)
		if err := newCIDREgressPolicy.Validate(); err != nil {
			return nil, err
		}

		calculatedPolicy.CIDRPolicy.Egress = newCIDREgressPolicy.Egress
		calculatedPolicy.L4Policy.Egress = newL4EgressPolicy.Egress
	}

	return calculatedPolicy, nil
}

// computePolicyEnforcementAndRules returns whether policy applies at ingress or ingress
// for the given security identity, as well as a list of any rules which select
// the set of labels of the given security identity.
//
// Must be called with repo mutex held for reading.
func (p *Repository) computePolicyEnforcementAndRules(securityIdentity *identity.Identity) (ingress bool, egress bool, matchingRules ruleSlice) {

	lbls := securityIdentity.LabelArray
	// Check if policy enforcement should be enabled at the daemon level.
	switch GetPolicyEnabled() {
	case option.AlwaysEnforce:
		_, _, matchingRules = p.getMatchingRules(securityIdentity)
		// If policy enforcement is enabled for the daemon, then it has to be
		// enabled for the endpoint.
		return true, true, matchingRules
	case option.DefaultEnforcement:
		ingress, egress, matchingRules = p.getMatchingRules(securityIdentity)
		// If the endpoint has the reserved:init label, i.e. if it has not yet
		// received any labels, always enforce policy (default deny).
		if lbls.Has(labels.IDNameInit) {
			return true, true, matchingRules
		}

		// Default mode means that if rules contain labels that match this
		// endpoint, then enable policy enforcement for this endpoint.
		return ingress, egress, matchingRules
	default:
		// If policy enforcement isn't enabled, we do not enable policy
		// enforcement for the endpoint. We don't care about returning any
		// rules that match.
		return false, false, nil
	}
}
