// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"encoding/json"
	"log/slog"
	"maps"
	"sync/atomic"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
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
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/policy/utils"
	"github.com/cilium/cilium/pkg/spanstat"
)

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
	GetSelectorPolicy(id *identity.Identity, skipRevision uint64, stats GetPolicyStatistics, endpointID uint64) (SelectorPolicy, uint64, error)

	// GetPolicySnapshot returns a map of all the SelectorPolicies in the repository.
	GetPolicySnapshot() map[identity.NumericIdentity]SelectorPolicy
	GetRevision() uint64
	GetRulesList() *models.Policy
	GetSelectorCache() *SelectorCache
	GetSubjectSelectorCache() *SelectorCache
	Iterate(f func(rule *types.PolicyEntry))
	ReplaceByResource(rules types.PolicyEntries, resource ipcachetypes.ResourceID) (affectedIDs *set.Set[identity.NumericIdentity], rev uint64, oldRevCnt int)
	Search() (types.PolicyEntries, uint64)
}

type GetPolicyStatistics interface {
	WaitingForPolicyRepository() *spanstat.SpanStat
	SelectorPolicyCalculation() *spanstat.SpanStat
}

// Repository is a list of policy rules which in combination form the security
// policy. A policy repository can be
type Repository struct {
	logger *slog.Logger
	// mutex protects the whole policy tree
	mutex lock.RWMutex

	rules            map[ruleKey]*rule
	rulesByNamespace map[string]sets.Set[ruleKey]
	rulesByResource  map[ipcachetypes.ResourceID]map[ruleKey]*rule

	// We will need a way to synthesize a rule key for rules without a resource;
	// This is only used for testing.
	nextID uint

	// revision is the revision of the policy repository. It will be
	// incremented whenever the policy repository is changed.
	// Always positive (>0).
	revision atomic.Uint64

	// selectorCache tracks the selectors used in the policies
	// resolved from the repository by alive endpoints.
	selectorCache *SelectorCache

	// subjectSelectorCache tracks the selectors used by policies
	// to select what endpoints they apply to
	subjectSelectorCache *SelectorCache

	// policyCache tracks the selector policies created from this repo
	policyCache *policyCache

	certManager certificatemanager.CertificateManager

	metricsManager    types.PolicyMetrics
	l7RulesTranslator envoypolicy.EnvoyL7RulesTranslator
}

func (p *Repository) GetEnvoyHTTPRules(l7Rules *api.L7Rules, ns string) (*cilium.HttpNetworkPolicyRules, bool) {
	return p.l7RulesTranslator.GetEnvoyHTTPRules(l7Rules, ns)
}

// GetSelectorCache() returns the selector cache used by the Repository
func (p *Repository) GetSelectorCache() *SelectorCache {
	return p.selectorCache
}

// GetSubjectSelectorCache returns the selector cache used by the Repository for indexing policies
func (p *Repository) GetSubjectSelectorCache() *SelectorCache {
	return p.subjectSelectorCache
}

// GetAuthTypes returns the AuthTypes required by the policy between the localID and remoteID
func (p *Repository) GetAuthTypes(localID, remoteID identity.NumericIdentity) AuthTypes {
	return p.policyCache.getAuthTypes(localID, remoteID)
}

// NewPolicyRepository creates a new policy repository.
func NewPolicyRepository(
	logger *slog.Logger,
	initialIDs identity.IdentityMap,
	certManager certificatemanager.CertificateManager,
	l7RulesTranslator envoypolicy.EnvoyL7RulesTranslator,
	idmgr identitymanager.IDManager,
	metricsManager types.PolicyMetrics,
) *Repository {
	selectorCache := NewSelectorCache(logger, initialIDs)
	subjectSelectorCache := NewSelectorCache(logger, nil)
	repo := &Repository{
		logger:               logger,
		rules:                make(map[ruleKey]*rule),
		rulesByNamespace:     make(map[string]sets.Set[ruleKey]),
		rulesByResource:      make(map[ipcachetypes.ResourceID]map[ruleKey]*rule),
		selectorCache:        selectorCache,
		subjectSelectorCache: subjectSelectorCache,
		certManager:          certManager,
		metricsManager:       metricsManager,
		l7RulesTranslator:    l7RulesTranslator,
	}
	repo.revision.Store(1)
	repo.policyCache = newPolicyCache(repo, idmgr)
	return repo
}

func (p *Repository) Search() (types.PolicyEntries, uint64) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.searchRLocked(), p.GetRevision()
}

// searchRLocked searches the policy repository for rules which match the
// specified labels and will return an array of all rules which matched.
func (p *Repository) searchRLocked() types.PolicyEntries {
	result := make(types.PolicyEntries, 0, len(p.rules))

	for _, r := range p.rules {
		result = append(result, &r.PolicyEntry)

	}

	return result
}

// addListLocked inserts a rule into the policy repository with the repository already locked
// Expects that the entire rule list has already been sanitized.
//
// Only used by unit tests, but by multiple packages.
func (p *Repository) addListLocked(entries types.PolicyEntries) (ruleSlice, uint64) {
	newRules := make(ruleSlice, 0, len(entries))
	for _, r := range entries {
		newRule := p.newRule(*r, ruleKey{idx: p.nextID})
		newRules = append(newRules, newRule)
		p.insert(newRule)
		p.nextID++
	}

	return newRules, p.BumpRevision()
}

func (p *Repository) insert(r *rule) {
	p.rules[r.key] = r
	p.metricsManager.AddRule(r.PolicyEntry)
	namespace := r.key.resource.Namespace()
	if _, ok := p.rulesByNamespace[namespace]; !ok {
		p.rulesByNamespace[namespace] = sets.New[ruleKey]()
	}
	p.rulesByNamespace[namespace].Insert(r.key)
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
	p.metricsManager.DelRule(r.PolicyEntry)
	delete(p.rules, key)
	namespace := r.key.resource.Namespace()
	p.rulesByNamespace[namespace].Delete(key)
	if len(p.rulesByNamespace[namespace]) == 0 {
		delete(p.rulesByNamespace, namespace)
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
func (p *Repository) newRule(policyEntry types.PolicyEntry, key ruleKey) *rule {
	r := &rule{
		PolicyEntry: policyEntry,
		key:         key,
	}
	css, _ := p.subjectSelectorCache.AddSelectors(r, makeStringLabels(r.Labels), r.Subject)
	r.subjectSelector = css[0]
	return r
}

// releaseRule releases the cached selector for a given rul
func (p *Repository) releaseRule(r *rule) {
	if r.subjectSelector != nil {
		p.subjectSelectorCache.RemoveSelector(r.subjectSelector, r)
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
	return p.MustAddPolicyEntries(utils.RulesToPolicyEntries(rules))
}

// MustAddList inserts a PolicyEntry into the policy repository. It is used for
// unit-testing purposes only.
func (p *Repository) MustAddPolicyEntries(entries types.PolicyEntries) (ruleSlice, uint64) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.addListLocked(entries)
}

// Iterate iterates the policy repository, calling f for each rule. It is safe
// to execute Iterate concurrently.
func (p *Repository) Iterate(f func(rule *types.PolicyEntry)) {
	p.mutex.RWMutex.Lock()
	defer p.mutex.RWMutex.Unlock()
	for _, r := range p.rules {
		f(&r.PolicyEntry)
	}
}

// JSONMarshalRules returns a slice of policy rules as string in JSON
// representation
func JSONMarshalRules(rules types.PolicyEntries) string {
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

	ruleList := p.searchRLocked()

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
		hasIngressDefaultDeny, hasEgressDefaultDeny,
		rulesIngress, rulesEgress := p.computePolicyEnforcementAndRules(securityIdentity)

	sc := p.GetSelectorCache()

	calculatedPolicy := &selectorPolicy{
		Revision:             p.GetRevision(),
		SelectorCache:        sc,
		L4Policy:             NewL4Policy(p.GetRevision()),
		IngressPolicyEnabled: ingressEnabled,
		EgressPolicyEnabled:  egressEnabled,
	}

	policyCtx := policyContext{
		repo:               p,
		ns:                 securityIdentity.LabelArray.Get(labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel),
		defaultDenyIngress: hasIngressDefaultDeny,
		defaultDenyEgress:  hasEgressDefaultDeny,
		traceEnabled:       option.Config.TracingEnabled(),
		logger:             p.logger.With(logfields.Identity, securityIdentity.ID),
	}

	if ingressEnabled {
		policyCtx.PolicyTrace("resolving ingress policy")
		newL4IngressPolicy, err := rulesIngress.resolveL4Policy(&policyCtx)
		if err != nil {
			return nil, err
		}
		calculatedPolicy.L4Policy.Ingress = newL4IngressPolicy
	}

	if egressEnabled {
		policyCtx.PolicyTrace("resolving egress policy")
		newL4EgressPolicy, err := rulesEgress.resolveL4Policy(&policyCtx)
		if err != nil {
			return nil, err
		}
		calculatedPolicy.L4Policy.Egress = newL4EgressPolicy
	}

	// Make the calculated policy ready for incremental updates
	calculatedPolicy.Attach(&policyCtx)

	// Commit selector changes
	sc.Commit()

	return calculatedPolicy, nil
}

// computePolicyEnforcementAndRules returns whether policy applies at ingress or ingress
// for the given security identity, as well as a sorted list of any rules which select
// the set of labels of the given security identity.
//
// Must be called with repo mutex held for reading.
func (p *Repository) computePolicyEnforcementAndRules(securityIdentity *identity.Identity) (
	hasIngress, hasEgress,
	hasIngressDefaultDeny, hasEgressDefaultDeny bool,
	rulesIngress, rulesEgress ruleSlice,
) {
	lbls := securityIdentity.LabelArray

	// Check if policy enforcement should be enabled at the daemon level.
	if lbls.Has(labels.IDNameHost) && !option.Config.EnableHostFirewall {
		return false, false, false, false, nil, nil
	}

	policyMode := GetPolicyEnabled()
	// If policy enforcement isn't enabled, we do not enable policy
	// enforcement for the endpoint. We don't care about returning any
	// rules that match.
	if policyMode == option.NeverEnforce {
		return false, false, false, false, nil, nil
	}

	rulesIngress = []*rule{}
	rulesEgress = []*rule{}
	// Match cluster-wide rules
	for rKey := range p.rulesByNamespace[""] {
		r := p.rules[rKey]
		if r.matchesSubject(securityIdentity) {
			if r.Ingress {
				rulesIngress = append(rulesIngress, r)
			} else {
				rulesEgress = append(rulesEgress, r)
			}
		}
	}
	// Match namespace-specific rules
	namespace, _ := lbls.LookupLabel(&podNamespaceLabel)
	if namespace != "" {
		for rKey := range p.rulesByNamespace[namespace] {
			r := p.rules[rKey]
			if r.matchesSubject(securityIdentity) {
				if r.Ingress {
					rulesIngress = append(rulesIngress, r)
				} else {
					rulesEgress = append(rulesEgress, r)
				}
			}
		}
	}

	// sort rules (in place) by priority
	rulesIngress.sort()
	rulesEgress.sort()

	// If policy enforcement is enabled for the daemon, then it has to be
	// enabled for the endpoint.
	// If the endpoint has the reserved:init label, i.e. if it has not yet
	// received any labels, always enforce policy (default deny).
	if policyMode == option.AlwaysEnforce || lbls.Has(labels.IDNameInit) {
		return true, true, true, true, rulesIngress, rulesEgress
	}

	// Determine the default policy for each direction.
	//
	// By default, endpoints have no policy and all traffic is allowed.
	// If any rules select the endpoint, then the endpoint switches to a
	// default-deny mode (same as traffic being enabled), per-direction.
	//
	// Rules, however, can optionally be configured to not enable default deny mode.
	// If no rules enable default-deny, then all traffic is allowed except that explicitly
	// denied by a Deny rule.
	//
	// There are three possible cases _per direction_:
	// 1: No rules are present,
	// 2: At least one default-deny rule is present. Then, policy is enabled
	// 3: Only non-default-deny rules are present. Then, policy is enabled, but we must insert
	//    an additional allow-all rule. We must do this, even if all traffic is allowed, because
	//    rules may have additional effects such as enabling L7 proxy.
	//    The wildcard rule is inserted to the last tier and priority.
	for _, r := range rulesIngress {
		hasIngress = true
		if r.DefaultDeny {
			hasIngressDefaultDeny = true
			break
		}
	}
	for _, r := range rulesEgress {
		hasEgress = true
		if r.DefaultDeny {
			hasEgressDefaultDeny = true
			break
		}
	}

	// If there only ingress default-allow rules, then insert a wildcard rule
	if !hasIngressDefaultDeny && hasIngress {
		// User the lowest tier and priority
		lastRule := rulesIngress[len(rulesIngress)-1]
		tier, priority := lastRule.Tier, lastRule.Priority
		// Keep the tier and priority as zeroes for backwards compatibility if the last rule
		// is at tier and priority 0.
		if tier > 0 || priority > 0 {
			tier++
			priority = 0
		}
		p.logger.Debug("Only default-allow policies, synthesizing ingress wildcard-allow rule",
			logfields.Identity, securityIdentity,
			logfields.Tier, tier,
			logfields.Priority, priority,
		)
		rulesIngress = append(rulesIngress, wildcardRule(securityIdentity, LabelsAllowAnyIngress, true /*ingress*/, tier, priority))
	}

	// Same for egress -- synthesize a wildcard rule
	if !hasEgressDefaultDeny && hasEgress {
		// User the lowest tier and priority
		lastRule := rulesEgress[len(rulesEgress)-1]
		tier, priority := lastRule.Tier, lastRule.Priority
		// Keep the tier and priority as zeroes for backwards compatibility if the last rule
		// is at tier and priority 0.
		if tier > 0 || priority > 0 {
			tier++
			priority = 0
		}
		p.logger.Debug("Only default-allow policies, synthesizing egress wildcard-allow rule",
			logfields.Identity, securityIdentity,
			logfields.Tier, tier,
			logfields.Priority, priority,
		)
		rulesEgress = append(rulesEgress, wildcardRule(securityIdentity, LabelsAllowAnyEgress, false /*egress*/, tier, priority))
	}

	return
}

// wildcardRule generates a wildcard rule that only selects the given subject identity.
func wildcardRule(subject *identity.Identity, lbls labels.LabelArray, ingress bool, tier types.Tier, priority float64) *rule {
	return &rule{
		PolicyEntry: types.PolicyEntry{
			Tier:     tier,
			Priority: priority,
			Verdict:  types.Allow,
			Ingress:  ingress,
			Subject:  types.NewLabelSelectorFromLabels(subject.LabelArray...),
			L3:       types.WildcardSelectors,
			Labels:   lbls,
		},
	}
}

// GetSelectorPolicy computes the SelectorPolicy for a given identity.
//
// It returns nil if skipRevision is >= than the already calculated version.
// This is used to skip policy calculation when a certain revision delta is
// known to not affect the given identity. Pass a skipRevision of 0 to force
// calculation.
func (r *Repository) GetSelectorPolicy(id *identity.Identity, skipRevision uint64, stats GetPolicyStatistics, endpointID uint64) (SelectorPolicy, uint64, error) {
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
	sp, updated, err := r.policyCache.updateSelectorPolicy(id, endpointID)
	stats.SelectorPolicyCalculation().EndError(err)

	// If we hit cache, reset the statistics.
	if !updated {
		stats.SelectorPolicyCalculation().Reset()
	}

	return sp, rev, err
}

// ReplaceByResource replaces all rules by resource, returning the complete set of affected endpoints.
func (p *Repository) ReplaceByResource(rules types.PolicyEntries, resource ipcachetypes.ResourceID) (affectedIDs *set.Set[identity.NumericIdentity], rev uint64, oldRuleCnt int) {
	if len(resource) == 0 {
		// This should never ever be hit, as the caller should have already validated the resource.
		// Out of paranoia, do nothing.
		p.logger.Error("Attempt to replace rules by resource with an empty resource.")
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

// GetPolicySnapshot returns a map of all the SelectorPolicies in the repository.
func (p *Repository) GetPolicySnapshot() map[identity.NumericIdentity]SelectorPolicy {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.policyCache.GetPolicySnapshot()
}
