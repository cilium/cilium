// Copyright 2016-2017 Authors of Cilium
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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
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
}

// NewPolicyRepository allocates a new policy repository
func NewPolicyRepository() *Repository {
	return &Repository{
		revision: 1,
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

// CanReachIngressRLocked evaluates the policy repository for the provided search
// context and returns the verdict or api.Undecided if no rule matches for
// ingress. The policy repository mutex must be held.
func (p *Repository) CanReachIngressRLocked(ctx *SearchContext) api.Decision {
	return p.rules.canReachIngressRLocked(ctx)
}

// AllowsIngressLabelAccess evaluates the policy repository for the provided search
// context and returns the verdict for ingress policy. If no matching policy
// allows for the  connection, the request will be denied. The policy repository
// mutex must be held.
func (p *Repository) AllowsIngressLabelAccess(ctx *SearchContext) api.Decision {
	ctx.PolicyTrace("Tracing %s\n", ctx.String())
	decision := api.Denied

	if len(p.rules) == 0 {
		ctx.PolicyTrace("  No rules found\n")
	} else {
		if p.CanReachIngressRLocked(ctx) == api.Allowed {
			decision = api.Allowed
		}
	}

	ctx.PolicyTrace("Label verdict: %s", decision.String())

	return decision
}

func wildcardL3L4Rule(proto api.L4Proto, port int, endpoints api.EndpointSelectorSlice,
	ruleLabels labels.LabelArray, l4Policy L4PolicyMap) {
	for k, filter := range l4Policy {
		if proto != filter.Protocol || (port != 0 && port != filter.Port) {
			continue
		}
		switch filter.L7Parser {
		case ParserTypeNone:
			continue
		case ParserTypeHTTP:
			// Wildcard at L7 all the endpoints allowed at L3 or L4.
			for _, sel := range endpoints {
				filter.L7RulesPerEp[sel] = api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				}
			}
		case ParserTypeKafka:
			// Wildcard at L7 all the endpoints allowed at L3 or L4.
			for _, sel := range endpoints {
				rule := api.PortRuleKafka{}
				rule.Sanitize()
				filter.L7RulesPerEp[sel] = api.L7Rules{
					Kafka: []api.PortRuleKafka{rule},
				}
			}
		case ParserTypeDNS:
			// Wildcard at L7 all the endpoints allowed at L3 or L4.
			for _, sel := range endpoints {
				rule := api.PortRuleDNS{}
				rule.Sanitize()
				filter.L7RulesPerEp[sel] = api.L7Rules{
					DNS: []api.PortRuleDNS{rule},
				}
			}
		default:
			// Wildcard at L7 all the endpoints allowed at L3 or L4.
			for _, sel := range endpoints {
				filter.L7RulesPerEp[sel] = api.L7Rules{
					L7Proto: filter.L7Parser.String(),
					L7:      []api.PortRuleL7{},
				}
			}
		}
		filter.Endpoints = append(filter.Endpoints, endpoints...)
		filter.DerivedFromRules = append(filter.DerivedFromRules, ruleLabels)
		l4Policy[k] = filter
	}
}

// wildcardL3L4Rules updates each ingress L7 rule to allow at L7 all traffic that
// is allowed at L3-only or L3/L4.
func (p *Repository) wildcardL3L4Rules(ctx *SearchContext, ingress bool, l4Policy L4PolicyMap) {
	p.rules.wildcardL3L4Rules(ctx, ingress, l4Policy)
}

// ResolveL4IngressPolicy resolves the L4 ingress policy for a set of endpoints
// by searching the policy repository for `PortRule` rules that are attached to
// a `Rule` where the EndpointSelector matches `ctx.To`. `ctx.From` takes no effect and
// is ignored in the search.  If multiple `PortRule` rules are found, all rules
// are merged together. If rules contains overlapping port definitions, the first
// rule found in the repository takes precedence.
//
// TODO: Coalesce l7 rules?
func (p *Repository) ResolveL4IngressPolicy(ctx *SearchContext) (*L4PolicyMap, error) {

	result, err := p.rules.resolveL4IngressPolicy(ctx, p.revision)
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
func (p *Repository) ResolveL4EgressPolicy(ctx *SearchContext) (*L4PolicyMap, error) {
	result, err := p.rules.resolveL4EgressPolicy(ctx, p.revision)

	if err != nil {
		return nil, err
	}

	return &result.Egress, nil
}

// ResolveCIDRPolicy resolves the L3 policy for a set of endpoints by searching
// the policy repository for `CIDR` rules that are attached to a `Rule`
// where the EndpointSelector matches `ctx.To`. `ctx.From` takes no effect and
// is ignored in the search.
func (p *Repository) ResolveCIDRPolicy(ctx *SearchContext) *CIDRPolicy {
	return p.rules.resolveCIDRPolicy(ctx)
}

func (p *Repository) allowsL4Egress(ctx *SearchContext) api.Decision {
	egressL4Policy, err := p.ResolveL4EgressPolicy(ctx)
	if err != nil {
		log.WithError(err).Warn("Evaluation error while resolving L4 egress policy")
	}
	verdict := api.Undecided
	if err == nil && len(*egressL4Policy) > 0 {
		verdict = egressL4Policy.EgressCoversContext(ctx)
	}

	if len(ctx.DPorts) == 0 {
		ctx.PolicyTrace("L4 egress verdict: [no port context specified]")
	} else {
		ctx.PolicyTrace("L4 egress verdict: %s", verdict.String())
	}

	return verdict
}

func (p *Repository) allowsL4Ingress(ctx *SearchContext) api.Decision {
	ingressPolicy, err := p.ResolveL4IngressPolicy(ctx)
	if err != nil {
		log.WithError(err).Warn("Evaluation error while resolving L4 ingress policy")
	}
	verdict := api.Undecided
	if err == nil && len(*ingressPolicy) > 0 {
		verdict = ingressPolicy.IngressCoversContext(ctx)
	}

	if len(ctx.DPorts) == 0 {
		ctx.PolicyTrace("L4 ingress verdict: [no port context specified]")
	} else {
		ctx.PolicyTrace("L4 ingress verdict: %s", verdict.String())
	}

	return verdict
}

// AllowsIngressRLocked evaluates the policy repository for the provided search
// context and returns the verdict for ingress. If no matching policy allows for
// the  connection, the request will be denied. The policy repository mutex must
// be held.
func (p *Repository) AllowsIngressRLocked(ctx *SearchContext) api.Decision {
	ctx.PolicyTrace("Tracing %s\n", ctx.String())
	decision := p.CanReachIngressRLocked(ctx)
	ctx.PolicyTrace("Label verdict: %s", decision.String())
	if decision == api.Allowed {
		ctx.PolicyTrace("L4 ingress policies skipped")
		return decision
	}

	// We only report the overall decision as L4 inclusive if a port has
	// been specified
	if len(ctx.DPorts) != 0 {
		decision = p.allowsL4Ingress(ctx)
	}

	if decision != api.Allowed {
		decision = api.Denied
	}
	return decision
}

// AllowsEgressRLocked evaluates the policy repository for the provided search
// context and returns the verdict. If no matching policy allows for the
// connection, the request will be denied. The policy repository mutex must be
// held.
func (p *Repository) AllowsEgressRLocked(egressCtx *SearchContext) api.Decision {
	egressCtx.PolicyTrace("Tracing %s\n", egressCtx.String())
	egressDecision := p.CanReachEgressRLocked(egressCtx)
	egressCtx.PolicyTrace("Egress label verdict: %s", egressDecision.String())

	if egressDecision == api.Allowed {
		egressCtx.PolicyTrace("L4 egress policies skipped")
		return egressDecision
	}
	if len(egressCtx.DPorts) != 0 {
		egressDecision = p.allowsL4Egress(egressCtx)
	}

	// If we cannot determine whether allowed at L4, undecided decision becomes
	// deny decision.
	if egressDecision != api.Allowed {
		egressDecision = api.Denied
	}

	return egressDecision
}

// AllowsEgressLabelAccess evaluates the policy repository for the provided search
// context and returns the verdict for egress. If no matching
// policy allows for the connection, the request will be denied.
// The policy repository mutex must be held.
func (p *Repository) AllowsEgressLabelAccess(egressCtx *SearchContext) api.Decision {
	egressCtx.PolicyTrace("Tracing %s\n", egressCtx.String())
	egressDecision := api.Denied
	if len(p.rules) == 0 {
		egressCtx.PolicyTrace("  No rules found\n")
	} else {
		egressDecision = p.CanReachEgressRLocked(egressCtx)
	}

	egressCtx.PolicyTrace("Egress label verdict: %s", egressDecision.String())

	return egressDecision
}

// CanReachEgressRLocked evaluates the policy repository for the provided search
// context and returns the verdict or api.Undecided if no rule matches for egress
// policy.
// The policy repository mutex must be held.
func (p *Repository) CanReachEgressRLocked(egressCtx *SearchContext) api.Decision {
	return p.rules.canReachEgressRLocked(egressCtx)
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

type RuleWithMetadata struct {
	Rule *api.Rule `json:"rule"`
	// localRuleConsumers is the set of the numeric identifiers which this rule
	// selects which are node-local (e.g., Endpoint).
	//
	// +optional
	LocalRuleConsumers map[uint16]*identity.Identity `json:"local-consumers"`

	// processedConsumers tracks which consumers have been 'processed' - that is,
	// it determines whether the consumer has actually been processed in relation
	// to this rule. It does *not* encode whether the rule selects the consumer;
	// that is what localRuleConsumers is for.
	//
	// +optional
	ProcessedConsumers map[uint16]struct{} `json:"processedConsumers"`
}

// SearchRLocked searches the policy repository for rules which match the
// specified labels and will return an array of all rules which matched.
func (p *Repository) SearchRLockedIan(labels labels.LabelArray) []*RuleWithMetadata {
	result := []*RuleWithMetadata{}

	for _, r := range p.rules {
		if r.Labels.Contains(labels) {
			result = append(result,
				&RuleWithMetadata{
					Rule:               &r.Rule,
					LocalRuleConsumers: r.localRuleConsumers,
					ProcessedConsumers: r.processedConsumers,
				})
		}
	}

	return result
}

// ContainsAllRLocked returns true if repository contains all the labels in
// needed. If needed contains no labels, ContainsAllRLocked() will always return
// true.
func (p *Repository) ContainsAllRLocked(needed labels.LabelArrayList) bool {
nextLabel:
	for _, neededLabel := range needed {
		for _, l := range p.rules {
			if len(l.Labels) > 0 && neededLabel.Contains(l.Labels) {
				continue nextLabel
			}
		}

		return false
	}

	return true
}

// Add inserts a rule into the policy repository
// This is just a helper function for unit testing.
// TODO: this should be in a test_helpers.go file or something similar
// so we can clearly delineate what helpers are for testing.
func (p *Repository) Add(r api.Rule, localRuleConsumers map[uint16]*identity.Identity) (uint64, map[uint16]struct{}, error) {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()

	if err := r.Sanitize(); err != nil {
		return p.revision, nil, err
	}

	newList := make([]*api.Rule, 1)
	newList[0] = &r
	rev := p.AddListLocked(newList, localRuleConsumers, NewEndpointIDSet(), &sync.WaitGroup{})
	return rev, map[uint16]struct{}{}, nil
}

func NewEndpointIDSet() *EndpointIDSet {
	return &EndpointIDSet{
		Eps: map[uint16]struct{}{},
	}
}

// AddListLocked inserts a rule into the policy repository with the repository already locked
// Expects that the entire rule list has already been sanitized.
func (p *Repository) AddListLocked(rules api.Rules, localRuleConsumers map[uint16]*identity.Identity, consumersToUpdate *EndpointIDSet, policySelectionWG *sync.WaitGroup) uint64 {
	log.Infof("AddListLocked: adding %d to WaitGroup", len(localRuleConsumers))
	policySelectionWG.Add(len(localRuleConsumers))

	newList := make([]*rule, len(rules))
	for i := range rules {
		newRule := &rule{
			Rule:               *rules[i],
			localRuleConsumers: map[uint16]*identity.Identity{},
			processedConsumers: map[uint16]struct{}{},
		}
		newList[i] = newRule
	}

	for identifier, securityIdentity := range localRuleConsumers {
		// Spawn goroutine per rule to avoid blocking on matching via API
		go AnalyzeWhetherRulesSelectEndpoint(identifier, securityIdentity, newList, consumersToUpdate, policySelectionWG)
	}

	p.rules = append(p.rules, newList...)
	p.revision++
	metrics.PolicyCount.Add(float64(len(newList)))
	metrics.PolicyRevision.Inc()

	return p.revision
}

func (p *Repository) UpdateLocalConsumers(identifiers map[uint16]*identity.Identity) *sync.WaitGroup {
	var policySelectionWG sync.WaitGroup
	for identifier, securityIdentity := range identifiers {
		policySelectionWG.Add(1)
		go AnalyzeWhetherRulesSelectEndpoint(identifier, securityIdentity, p.rules, NewEndpointIDSet(), &policySelectionWG)
	}
	return &policySelectionWG
}

func (r *rule) updateLocalConsumers(identifiers map[uint16]*identity.Identity) map[uint16]struct{} {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	consumersToUpdate := map[uint16]struct{}{}

	log.Infof("updateLocalConsumers: identifiers provided: %v", identifiers)

	for id, securityIdentity := range identifiers {
		ruleMatches := r.EndpointSelector.Matches(securityIdentity.LabelArray)
		log.Infof("updateLocalConsumers: ruleMatches identifier %d --> %v ? : %v", id, securityIdentity, ruleMatches)
		if ruleMatches {
			if r.localRuleConsumers == nil {
				r.localRuleConsumers = map[uint16]*identity.Identity{}
			}
			r.localRuleConsumers[id] = securityIdentity
			consumersToUpdate[id] = struct{}{}
		}
		if r.processedConsumers == nil {
			r.processedConsumers = map[uint16]struct{}{}
		}
		r.processedConsumers[id] = struct{}{}
	}
	log.Infof("updateLocalConsumers: rule %v: localConsumers: %v", r.Rule, r.localRuleConsumers)
	log.Infof("updateLocalConsumers: consumersToUpdate = %v", consumersToUpdate)

	return consumersToUpdate
}

// AddList inserts a rule into the policy repository.
func (p *Repository) AddList(rules api.Rules) uint64 {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	// TODO (ianvernon) plumbing
	return p.AddListLocked(rules, map[uint16]*identity.Identity{}, NewEndpointIDSet(), &sync.WaitGroup{})
}

type EndpointIDSet struct {
	Mutex lock.RWMutex
	Eps   map[uint16]struct{}
}

// DeleteByLabelsLocked deletes all rules in the policy repository which
// contain the specified labels. Returns the revision of the policy repository
// after deleting the rules, as well as now many rules were deleted.
func (p *Repository) DeleteByLabelsLocked(labels labels.LabelArray, localConsumers map[uint16]*identity.Identity, consumersToUpdate *EndpointIDSet, policySelectionWG *sync.WaitGroup) (uint64, int) {
	log.Infof("DeleteByLabelsLocked: adding %d to WaitGroup", len(localConsumers))
	policySelectionWG.Add(len(localConsumers))

	deleted := 0
	new := p.rules[:0]
	deletedRules := []*rule{}

	for _, r := range p.rules {
		if !r.Labels.Contains(labels) {
			new = append(new, r)
		} else {
			deletedRules = append(deletedRules, r)
			deleted++
		}
	}

	for identifier, securityIdentity := range localConsumers {
		// Spawn goroutine to determine whether deleted rules select endpointss
		go AnalyzeWhetherRulesSelectEndpoint(identifier, securityIdentity, deletedRules, consumersToUpdate, policySelectionWG)
	}

	if deleted > 0 {
		p.revision++
		p.rules = new
		metrics.PolicyCount.Sub(float64(deleted))
		metrics.PolicyRevision.Inc()
	}

	return p.revision, deleted
}

func AnalyzeWhetherRulesSelectEndpoint(id uint16, secID *identity.Identity, newRuleList []*rule, set *EndpointIDSet, wg *sync.WaitGroup) {
	for _, r := range newRuleList {
		ruleMatches := r.EndpointSelector.Matches(secID.LabelArray)
		log.Infof("AnalyzeWhetherRulesSelectEndpoint: ruleMatches identifier %d --> %v ? : %v", id, secID, ruleMatches)
		r.mutex.Lock()
		if ruleMatches {
			set.Mutex.Lock()
			set.Eps[id] = struct{}{}
			set.Mutex.Unlock()
			if r.localRuleConsumers == nil {
				r.localRuleConsumers = map[uint16]*identity.Identity{}
			}
			r.localRuleConsumers[id] = secID
		}
		if r.processedConsumers == nil {
			r.processedConsumers = map[uint16]struct{}{}
		}
		r.processedConsumers[id] = struct{}{}
		r.mutex.Unlock()
	}
	// Work has been done for calculating change for this endpoint in relation
	// to rules that have been deleted.
	wg.Done()
}

// DeleteByLabels deletes all rules in the policy repository which contain the
// specified labels
func (p *Repository) DeleteByLabels(labels labels.LabelArray) (uint64, int) {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	return p.DeleteByLabelsLocked(labels, map[uint16]*identity.Identity{}, NewEndpointIDSet(), &sync.WaitGroup{})
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

// JSONMarshalRulesIa  returns a slice of policy rules as string in JSON
// representation
func JSONMarshalRulesIan(rules []*RuleWithMetadata) string {
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
// rule with labels matching the labels in the provided LabelArray, as well as
// a slice of all rules which match.
//
// Must be called with p.Mutex held
func (p *Repository) getMatchingRules(id uint16, securityIdentity *identity.Identity) (ingressMatch bool, egressMatch bool, matchingRules []*rule) {
	labels := securityIdentity.LabelArray

	matchingRules = []*rule{}
	ingressMatch = false
	egressMatch = false
	for _, r := range p.rules {
		r.mutex.Lock()
		var ruleMatches bool
		if r.processedConsumers == nil {
			r.processedConsumers = map[uint16]struct{}{}
		}
		if r.localRuleConsumers == nil {
			r.localRuleConsumers = map[uint16]*identity.Identity{}
		}
		if _, ok := r.processedConsumers[id]; ok {
			if _, ok := r.localRuleConsumers[id]; ok {
				ruleMatches = true
			}
		} else {
			ruleMatches = r.EndpointSelector.Matches(labels)
			// Rule has been processed, can update now cache within rule now.
			if ruleMatches {
				r.localRuleConsumers[id] = securityIdentity
			}
			r.processedConsumers[id] = struct{}{}
		}
		if ruleMatches {
			if len(r.Ingress) > 0 {
				ingressMatch = true
			}
			if len(r.Egress) > 0 {
				egressMatch = true
			}
			matchingRules = append(matchingRules, r)
		}
		r.mutex.Unlock()
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
	return p.revision
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
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	p.revision++
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

// ResolvePolicy returns the EndpointPolicy for the provided set of labels against the
// set of rules in the repository, and the provided set of identities.
// If the policy cannot be generated due to conflicts at L4 or L7, returns an
// error.
func (p *Repository) ResolvePolicy(id uint16, securityIdentity *identity.Identity, policyOwner PolicyOwner, identityCache cache.IdentityCache) (*EndpointPolicy, error) {

	labels := securityIdentity.LabelArray

	calculatedPolicy := &EndpointPolicy{
		ID:                      id,
		L4Policy:                NewL4Policy(),
		CIDRPolicy:              NewCIDRPolicy(),
		PolicyMapState:          make(MapState),
		PolicyOwner:             policyOwner,
		DeniedIngressIdentities: cache.IdentityCache{},
		DeniedEgressIdentities:  cache.IdentityCache{},
	}

	// First obtain whether policy applies in both traffic directions, as well
	// as list of rules which actually select this endpoint. This allows us
	// to not have to iterate through the entire rule list multiple times and
	// perform the matching decision again when computing policy for each
	// protocol layer, which is quite costly in terms of performance.
	ingressEnabled, egressEnabled, matchingRules := p.computePolicyEnforcementAndRules(id, securityIdentity)
	calculatedPolicy.IngressPolicyEnabled = ingressEnabled
	calculatedPolicy.EgressPolicyEnabled = egressEnabled

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

	if ingressEnabled {
		newL4IngressPolicy, err := matchingRules.resolveL4IngressPolicy(&ingressCtx, p.revision)
		if err != nil {
			return nil, err
		}

		newCIDRIngressPolicy := matchingRules.resolveCIDRPolicy(&ingressCtx)
		if err := newCIDRIngressPolicy.Validate(); err != nil {
			return nil, err
		}

		calculatedPolicy.CIDRPolicy.Ingress = newCIDRIngressPolicy.Ingress
		calculatedPolicy.L4Policy.Ingress = newL4IngressPolicy.Ingress

		for identity, labels := range identityCache {
			ingressCtx.From = labels
			egressCtx.To = labels

			ingressAccess := matchingRules.canReachIngressRLocked(&ingressCtx)
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

	if egressEnabled {
		newL4EgressPolicy, err := matchingRules.resolveL4EgressPolicy(&egressCtx, p.revision)
		if err != nil {
			return nil, err
		}

		newCIDREgressPolicy := matchingRules.resolveCIDRPolicy(&egressCtx)
		if err := newCIDREgressPolicy.Validate(); err != nil {
			return nil, err
		}

		calculatedPolicy.CIDRPolicy.Egress = newCIDREgressPolicy.Egress
		calculatedPolicy.L4Policy.Egress = newL4EgressPolicy.Egress

		for identity, labels := range identityCache {
			egressCtx.To = labels

			egressAccess := matchingRules.canReachEgressRLocked(&egressCtx)
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
		// Allow all identities
		calculatedPolicy.PolicyMapState.AllowAllIdentities(identityCache, trafficdirection.Egress)
	}

	calculatedPolicy.computeDesiredL4PolicyMapEntries(identityCache)
	calculatedPolicy.PolicyMapState.DetermineAllowLocalhost(calculatedPolicy.L4Policy)
	calculatedPolicy.PolicyMapState.DetermineAllowFromWorld()

	return calculatedPolicy, nil
}

// computePolicyEnforcementAndRules returns whether policy applies at ingress or ingress
// for the given set of labels, as well as a list of any rules which select
// the set of labels.
//
// Must be called with repo mutex held for reading.
func (p *Repository) computePolicyEnforcementAndRules(id uint16, securityIdentity *identity.Identity) (ingress bool, egress bool, matchingRules ruleSlice) {

	lbls := securityIdentity.LabelArray
	// Check if policy enforcement should be enabled at the daemon level.
	switch GetPolicyEnabled() {
	case option.AlwaysEnforce:
		_, _, matchingRules = p.getMatchingRules(id, securityIdentity)
		// If policy enforcement is enabled for the daemon, then it has to be
		// enabled for the endpoint.
		return true, true, matchingRules
	case option.DefaultEnforcement:
		ingress, egress, matchingRules = p.getMatchingRules(id, securityIdentity)
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
