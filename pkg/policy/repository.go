// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sync/atomic"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/spanstat"
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
	GetTLSContext(tls *api.TLSContext) (ca, public, private string, inlineSecrets bool, err error)

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
func (p *policyContext) GetTLSContext(tls *api.TLSContext) (ca, public, private string, inlineSecrets bool, err error) {
	if p.repo.certManager == nil {
		return "", "", "", false, fmt.Errorf("No Certificate Manager set on Policy Repository")
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

type PolicyRepository interface {
	BumpRevision() uint64
	GetAuthTypes(localID identity.NumericIdentity, remoteID identity.NumericIdentity) AuthTypes
	GetEnvoyHTTPRules(l7Rules *api.L7Rules, ns string) (*cilium.HttpNetworkPolicyRules, bool)

	// GetSelectorPolicy computes the SelectorPolicy for a given identity.
	//
	// It returns nil if skipRevision is >= than the already calculated version.
	// This is used to skip policy calculation when a certain revision delta is
	// known to not affect the given identity. Pass a skipRevision of 0 to force
	// calculation.
	GetSelectorPolicy(id *identity.Identity, skipRevision uint64, stats GetPolicyStatistics) (SelectorPolicy, uint64, error)

	// GetPolicySnapshot returns a map of all the SelectorPolicies in the repository.
	GetPolicySnapshot() map[identity.NumericIdentity]SelectorPolicy
	GetRevision() uint64
	GetRulesList() *models.Policy
	GetSelectorCache() *SelectorCache
	Iterate(f func(rule *api.Rule))
	ReplaceByResource(rules api.Rules, resource ipcachetypes.ResourceID) (affectedIDs *set.Set[identity.NumericIdentity], rev uint64, oldRevCnt int)
	ReplaceByLabels(rules api.Rules, searchLabelsList []labels.LabelArray) (affectedIDs *set.Set[identity.NumericIdentity], rev uint64, oldRevCnt int)
	Search(lbls labels.LabelArray) (api.Rules, uint64)
	SetEnvoyRulesFunc(f func(certificatemanager.SecretManager, *api.L7Rules, string, string) (*cilium.HttpNetworkPolicyRules, bool))
}

type GetPolicyStatistics interface {
	WaitingForPolicyRepository() *spanstat.SpanStat
	SelectorPolicyCalculation() *spanstat.SpanStat
}

// Repository is a list of policy rules which in combination form the security
// policy. A policy repository can be
type Repository struct {
	// mutex protects the whole policy tree
	mutex lock.RWMutex

	rules            map[ruleKey]*rule
	rulesByNamespace map[string]sets.Set[ruleKey]
	rulesByResource  map[ipcachetypes.ResourceID]map[ruleKey]*rule

	// We will need a way to synthesize a rule key for rules without a resource;
	// these are - in practice - very rare, as they only come from the local API,
	// never via k8s.
	nextID uint

	// revision is the revision of the policy repository. It will be
	// incremented whenever the policy repository is changed.
	// Always positive (>0).
	revision atomic.Uint64

	// SelectorCache tracks the selectors used in the policies
	// resolved from the repository.
	selectorCache *SelectorCache

	// PolicyCache tracks the selector policies created from this repo
	policyCache *policyCache

	certManager   certificatemanager.CertificateManager
	secretManager certificatemanager.SecretManager

	getEnvoyHTTPRules func(certificatemanager.SecretManager, *api.L7Rules, string, string) (*cilium.HttpNetworkPolicyRules, bool)

	metricsManager api.PolicyMetrics
}

// GetSelectorCache() returns the selector cache used by the Repository
func (p *Repository) GetSelectorCache() *SelectorCache {
	return p.selectorCache
}

// GetAuthTypes returns the AuthTypes required by the policy between the localID and remoteID
func (p *Repository) GetAuthTypes(localID, remoteID identity.NumericIdentity) AuthTypes {
	return p.policyCache.getAuthTypes(localID, remoteID)
}

func (p *Repository) SetEnvoyRulesFunc(f func(certificatemanager.SecretManager, *api.L7Rules, string, string) (*cilium.HttpNetworkPolicyRules, bool)) {
	p.getEnvoyHTTPRules = f
}

func (p *Repository) GetEnvoyHTTPRules(l7Rules *api.L7Rules, ns string) (*cilium.HttpNetworkPolicyRules, bool) {
	if p.getEnvoyHTTPRules == nil {
		return nil, true
	}
	return p.getEnvoyHTTPRules(p.secretManager, l7Rules, ns, p.secretManager.GetSecretSyncNamespace())
}

// NewPolicyRepository creates a new policy repository.
func NewPolicyRepository(
	initialIDs identity.IdentityMap,
	certManager certificatemanager.CertificateManager,
	secretManager certificatemanager.SecretManager,
	idmgr identitymanager.IDManager,
	metricsManager api.PolicyMetrics,
) *Repository {
	selectorCache := NewSelectorCache(initialIDs)
	repo := &Repository{
		rules:            make(map[ruleKey]*rule),
		rulesByNamespace: make(map[string]sets.Set[ruleKey]),
		rulesByResource:  make(map[ipcachetypes.ResourceID]map[ruleKey]*rule),
		selectorCache:    selectorCache,
		certManager:      certManager,
		secretManager:    secretManager,
		metricsManager:   metricsManager,
	}
	repo.revision.Store(1)
	repo.policyCache = newPolicyCache(repo, idmgr)
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

func (p *Repository) Search(lbls labels.LabelArray) (api.Rules, uint64) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.searchRLocked(lbls), p.GetRevision()
}

// searchRLocked searches the policy repository for rules which match the
// specified labels and will return an array of all rules which matched.
func (p *Repository) searchRLocked(lbls labels.LabelArray) api.Rules {
	result := api.Rules{}

	for _, r := range p.rules {
		if r.Labels.Contains(lbls) {
			result = append(result, &r.Rule)
		}
	}

	return result
}

// addListLocked inserts a rule into the policy repository with the repository already locked
// Expects that the entire rule list has already been sanitized.
//
// Only used by unit tests, but by multiple packages.
func (p *Repository) addListLocked(rules api.Rules) (ruleSlice, uint64) {
	newRules := make(ruleSlice, 0, len(rules))
	for _, r := range rules {
		newRule := p.newRule(*r, ruleKey{idx: p.nextID})
		newRules = append(newRules, newRule)
		p.insert(newRule)
		p.nextID++
	}

	return newRules, p.BumpRevision()
}

func (p *Repository) insert(r *rule) {
	p.rules[r.key] = r
	p.metricsManager.AddRule(r.Rule)
	if _, ok := p.rulesByNamespace[r.key.resource.Namespace()]; !ok {
		p.rulesByNamespace[r.key.resource.Namespace()] = sets.New[ruleKey]()
	}
	p.rulesByNamespace[r.key.resource.Namespace()].Insert(r.key)
	rid := r.key.resource
	if len(rid) > 0 {
		if p.rulesByResource[rid] == nil {
			p.rulesByResource[rid] = map[ruleKey]*rule{}
		}
		p.rulesByResource[rid][r.key] = r
	}

	metrics.Policy.Inc()
}

func (p *Repository) del(key ruleKey) {
	r := p.rules[key]
	if r == nil {
		return
	}
	p.metricsManager.DelRule(r.Rule)
	delete(p.rules, key)
	p.rulesByNamespace[key.resource.Namespace()].Delete(key)
	if len(p.rulesByNamespace[key.resource.Namespace()]) == 0 {
		delete(p.rulesByNamespace, key.resource.Namespace())
	}

	rid := key.resource
	if len(rid) > 0 && p.rulesByResource[rid] != nil {
		delete(p.rulesByResource[rid], key)
		if len(p.rulesByResource[rid]) == 0 {
			delete(p.rulesByResource, rid)
		}
	}
	metrics.Policy.Dec()
}

// newRule allocates a CachedSelector for a given rule.
func (p *Repository) newRule(apiRule api.Rule, key ruleKey) *rule {
	r := &rule{
		Rule: apiRule,
		key:  key,
	}
	r.subjectSelector, _ = p.selectorCache.AddIdentitySelector(r, makeStringLabels(r.Labels), *r.getSelector())
	return r
}

// releaseRule releases the cached selector for a given rul
func (p *Repository) releaseRule(r *rule) {
	if r.subjectSelector != nil {
		p.selectorCache.RemoveSelector(r.subjectSelector, r)
	}
}

// MustAddList inserts a rule into the policy repository. It is used for
// unit-testing purposes only. Panics if the rule is invalid
func (p *Repository) MustAddList(rules api.Rules) (ruleSlice, uint64) {
	for i := range rules {
		err := rules[i].Sanitize()
		if err != nil {
			panic(err)
		}
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.addListLocked(rules)
}

// Iterate iterates the policy repository, calling f for each rule. It is safe
// to execute Iterate concurrently.
func (p *Repository) Iterate(f func(rule *api.Rule)) {
	p.mutex.RWMutex.Lock()
	defer p.mutex.RWMutex.Unlock()
	for _, r := range p.rules {
		f(&r.Rule)
	}
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

// GetRevision returns the revision of the policy repository
func (p *Repository) GetRevision() uint64 {
	return p.revision.Load()
}

// BumpRevision allows forcing policy regeneration
func (p *Repository) BumpRevision() uint64 {
	metrics.PolicyRevision.Inc()
	return p.revision.Add(1)
}

// GetRulesList returns the current policy
func (p *Repository) GetRulesList() *models.Policy {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	lbls := labels.ParseSelectLabelArrayFromArray([]string{})
	ruleList := p.searchRLocked(lbls)

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
		matchingRules := p.computePolicyEnforcementAndRules(securityIdentity)

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
	// Match cluster-wide rules
	for rKey := range p.rulesByNamespace[""] {
		r := p.rules[rKey]
		if r.matchesSubject(securityIdentity) {
			matchingRules = append(matchingRules, r)
		}
	}
	// Match namespace-specific rules
	namespace := lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel)
	if namespace != "" {
		for rKey := range p.rulesByNamespace[namespace] {
			r := p.rules[rKey]
			if r.matchesSubject(securityIdentity) {
				matchingRules = append(matchingRules, r)
			}
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
		log.WithField(logfields.Identity, securityIdentity).Debug("Only default-allow policies, synthesizing ingress wildcard-allow rule")
		matchingRules = append(matchingRules, wildcardRule(securityIdentity.LabelArray, true /*ingress*/))
	}

	// Same for egress -- synthesize a wildcard rule
	if !hasEgressDefaultDeny && egress {
		log.WithField(logfields.Identity, securityIdentity).Debug("Only default-allow policies, synthesizing egress wildcard-allow rule")
		matchingRules = append(matchingRules, wildcardRule(securityIdentity.LabelArray, false /*egress*/))
	}

	return
}

// wildcardRule generates a wildcard rule that only selects the given identity.
func wildcardRule(lbls labels.LabelArray, ingress bool) *rule {
	r := &rule{}

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

// GetSelectorPolicy computes the SelectorPolicy for a given identity.
//
// It returns nil if skipRevision is >= than the already calculated version.
// This is used to skip policy calculation when a certain revision delta is
// known to not affect the given identity. Pass a skipRevision of 0 to force
// calculation.
func (r *Repository) GetSelectorPolicy(id *identity.Identity, skipRevision uint64, stats GetPolicyStatistics) (SelectorPolicy, uint64, error) {
	stats.WaitingForPolicyRepository().Start()
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	stats.WaitingForPolicyRepository().End(true)

	rev := r.GetRevision()

	// Do we already have a given revision?
	// If so, skip calculation.
	if skipRevision >= rev {
		return nil, rev, nil
	}

	stats.SelectorPolicyCalculation().Start()
	// This may call back in to the (locked) repository to generate the
	// selector policy
	sp, updated, err := r.policyCache.updateSelectorPolicy(id)
	stats.SelectorPolicyCalculation().EndError(err)

	// If we hit cache, reset the statistics.
	if !updated {
		stats.SelectorPolicyCalculation().Reset()
	}

	return sp, rev, err
}

// ReplaceByResource replaces all rules by resource, returning the complete set of affected endpoints.
func (p *Repository) ReplaceByResource(rules api.Rules, resource ipcachetypes.ResourceID) (affectedIDs *set.Set[identity.NumericIdentity], rev uint64, oldRuleCnt int) {
	if len(resource) == 0 {
		// This should never ever be hit, as the caller should have already validated the resource.
		// Out of paranoia, do nothing.
		log.Error("Attempt to replace rules by resource with an empty resource.")
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	affectedIDs = &set.Set[identity.NumericIdentity]{}
	oldRules := maps.Clone(p.rulesByResource[resource]) // need to clone as `p.del()` mutates this

	for key, oldRule := range oldRules {
		for _, subj := range oldRule.getSubjects() {
			affectedIDs.Insert(subj)
		}
		p.del(key)
	}

	if len(rules) > 0 {
		p.rulesByResource[resource] = make(map[ruleKey]*rule, len(rules))
		for i, r := range rules {
			newRule := p.newRule(*r, ruleKey{resource: resource, idx: uint(i)})
			p.insert(newRule)

			for _, subj := range newRule.getSubjects() {
				affectedIDs.Insert(subj)
			}
		}
	}

	// Now that selectors have been allocated for new rules,
	// we may release the old ones.
	for _, r := range oldRules {
		p.releaseRule(r)
	}

	return affectedIDs, p.BumpRevision(), len(oldRules)
}

// ReplaceByLabels implements the somewhat awkward REST local API for providing network policy,
// where the "key" is a list of labels, possibly multiple, that should be removed before
// installing the new rules.
func (p *Repository) ReplaceByLabels(rules api.Rules, searchLabelsList []labels.LabelArray) (affectedIDs *set.Set[identity.NumericIdentity], rev uint64, oldRuleCnt int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var oldRules []*rule
	affectedIDs = &set.Set[identity.NumericIdentity]{}

	// determine outgoing rules
	for ruleKey, rule := range p.rules {
		for _, searchLabels := range searchLabelsList {
			if rule.Labels.Contains(searchLabels) {
				p.del(ruleKey)
				oldRules = append(oldRules, rule)
				break
			}
		}
	}

	// Insert new rules, allocating a subject selector
	for _, r := range rules {
		newRule := p.newRule(*r, ruleKey{idx: p.nextID})
		p.insert(newRule)
		p.nextID++

		for _, nid := range newRule.getSubjects() {
			affectedIDs.Insert(nid)
		}
	}

	// Now that subject selectors have been allocated, release the old rules.
	for _, oldRule := range oldRules {
		for _, nid := range oldRule.getSubjects() {
			affectedIDs.Insert(nid)
		}
		p.releaseRule(oldRule)
	}

	return affectedIDs, p.BumpRevision(), len(oldRules)
}

// GetPolicySnapshot returns a map of all the SelectorPolicies in the repository.
func (p *Repository) GetPolicySnapshot() map[identity.NumericIdentity]SelectorPolicy {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.policyCache.GetPolicySnapshot()
}
