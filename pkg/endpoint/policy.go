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

package endpoint

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
)

// optionEnabled  and optionDisabled are used
// to fill the models.ConfigurationMap opt state
const (
	optionEnabled  = "enabled"
	optionDisabled = "disabled"
)

func (e *Endpoint) checkEgressAccess(owner Owner, dstLabels labels.LabelArray, opts models.ConfigurationMap, opt string) {
	ctx := policy.SearchContext{
		From: e.Consumable.LabelArray,
		To:   dstLabels,
	}

	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}

	scopedLog := e.getLogger().WithFields(logrus.Fields{
		logfields.Labels + ".from": ctx.From,
		logfields.Labels + ".to":   ctx.To,
	})

	switch owner.GetPolicyRepository().AllowsLabelAccess(&ctx) {
	case api.Allowed:
		opts[opt] = optionEnabled
		scopedLog.Debug("checkEgressAccess: Enabled")
	case api.Denied:
		opts[opt] = optionDisabled
		scopedLog.Debug("checkEgressAccess: Disabled")
	}
}

// allowConsumer must be called with global endpoint.Mutex held
func (e *Endpoint) allowConsumer(owner Owner, id policy.NumericIdentity) bool {
	cache := policy.GetConsumableCache()
	if !e.Opts.IsEnabled(OptionConntrack) {
		return e.Consumable.AllowConsumerAndReverseLocked(cache, id)
	}
	return e.Consumable.AllowConsumerLocked(cache, id)
}

// ProxyID returns a unique string to identify a proxy mapping
func (e *Endpoint) ProxyID(l4 *policy.L4Filter) string {
	direction := "ingress"
	if !l4.Ingress {
		direction = "egress"
	}
	return fmt.Sprintf("%d:%s:%s:%d", e.ID, direction, l4.Protocol, l4.Port)
}

func (e *Endpoint) addRedirect(owner Owner, l4 *policy.L4Filter) (uint16, error) {
	return owner.UpdateProxyRedirect(e, l4)
}

// Called with endpoint lock Write locked!
func (e *Endpoint) collectUnusedRedirects(oldMap, newMap policy.L4PolicyMap) {
	if e.proxiesToRemove == nil {
		e.proxiesToRemove = make(map[string]bool)
	}

	for k, v := range oldMap {
		if newMap != nil {
			// Keep redirects which are also in the new policy
			if _, ok := newMap[k]; ok {
				continue
			}
		}

		if v.IsRedirect() {
			e.proxiesToRemove[e.ProxyID(&v)] = true
		}
	}
}

// Called with endpoint lock Write locked!
func (e *Endpoint) removeCollectedRedirects(owner Owner) {
	for id := range e.proxiesToRemove {
		if err := owner.RemoveProxyRedirect(e, id); err != nil {
			e.getLogger().WithError(err).WithField(logfields.L4PolicyID, id).Warn("Error while removing proxy redirect")
		}
		delete(e.proxiesToRemove, id)
	}
}

func getSecurityIdentities(labelsMap *policy.IdentityCache, selector *api.EndpointSelector) []policy.NumericIdentity {
	identities := []policy.NumericIdentity{}
	for idx, labels := range *labelsMap {
		if selector.Matches(labels) {
			log.WithFields(logrus.Fields{
				logfields.IdentityLabels: labels,
				logfields.L4PolicyID:     idx,
			}).Debug("L4 Policy matches")
			identities = append(identities, idx)
		}
	}

	return identities
}

// removeOldFilter removes the old l4 filter from the endpoint.
// Returns a map that represents all policies that were attempted to be removed;
// it maps to whether they were removed successfully (true or false)
func (e *Endpoint) removeOldFilter(owner Owner, labelsMap *policy.IdentityCache,
	filter *policy.L4Filter) policy.SecurityIDContexts {

	fromEndpointsSrcIDs := policy.NewSecurityIDContexts()
	port := uint16(filter.Port)
	proto := uint8(filter.U8Proto)

	for _, sel := range filter.FromEndpoints {
		for _, id := range getSecurityIdentities(labelsMap, &sel) {
			srcID := id.Uint32()
			l4RuleCtx, l7RuleCtx := policy.ParseL4Filter(*filter)
			if _, ok := fromEndpointsSrcIDs[id]; !ok {
				fromEndpointsSrcIDs[id] = policy.NewL4RuleContexts()
			}
			if err := e.PolicyMap.DeleteL4(srcID, port, proto); err != nil {
				// This happens when the policy would add
				// multiple copies of the same L4 policy. Only
				// one of them is actually added, but we'll
				// still try to remove it multiple times.
				e.getLogger().WithError(err).WithField(logfields.L4PolicyID, srcID).Debug("Delete old l4 policy failed")
				// Set with false only if the key was not
				// previously set nor the value was set
				// with true. Since we can have multiple
				// copies of the same L4 policy, a single
				// successful DeleteL4 means the policy
				// was actually removed.
				v, ok := fromEndpointsSrcIDs[id][l4RuleCtx]
				if ok && !v.L4Installed {
					fromEndpointsSrcIDs[id][l4RuleCtx] = l7RuleCtx
				}
			} else {
				l7RuleCtx.L4Installed = true
				fromEndpointsSrcIDs[id][l4RuleCtx] = l7RuleCtx
			}
		}
	}

	return fromEndpointsSrcIDs
}

// applyNewFilter adds the given l4 filter to the endpoint.
// Returns a map that represents all policies that were attempted to be added;
// it maps to whether they were added successfully (true or false).
// It also returns the number of errors that occurred while when applying the
// policy.
// Applies for L3 dependent L4 not for L4-only.
func (e *Endpoint) applyNewFilter(owner Owner, labelsMap *policy.IdentityCache,
	filter *policy.L4Filter) (policy.SecurityIDContexts, int) {

	fromEndpointsSrcIDs := policy.NewSecurityIDContexts()
	port := uint16(filter.Port)
	proto := uint8(filter.U8Proto)

	errors := 0
	for _, sel := range filter.FromEndpoints {
		for _, id := range getSecurityIdentities(labelsMap, &sel) {
			srcID := id.Uint32()
			if e.PolicyMap.L4Exists(srcID, port, proto) {
				e.getLogger().WithField("l4Filter", filter).Debug("L4 filter exists")
				continue
			}
			l4RuleCtx, l7RuleCtx := policy.ParseL4Filter(*filter)
			if _, ok := fromEndpointsSrcIDs[id]; !ok {
				fromEndpointsSrcIDs[id] = policy.NewL4RuleContexts()
			}
			if err := e.PolicyMap.AllowL4(srcID, port, proto); err != nil {
				e.getLogger().WithFields(logrus.Fields{
					logfields.PolicyID: srcID,
					logfields.Port:     port,
					logfields.Protocol: proto}).WithError(err).Warn(
					"Update of l4 policy map failed")
				errors++
				l7RuleCtx.L4Installed = false
				fromEndpointsSrcIDs[id][l4RuleCtx] = l7RuleCtx
			} else {
				l7RuleCtx.L4Installed = true
				fromEndpointsSrcIDs[id][l4RuleCtx] = l7RuleCtx
			}
		}
	}
	return fromEndpointsSrcIDs, errors
}

// setMapOperationResult iterates over the newSecIDs and sets their result
// to the secIDs map only when either:
//  - It is the first time an assignment is being done to this
//    key and the value is true OR
//  - The previous assigned value and the new value are both
//    true
func setMapOperationResult(secIDs, newSecIDs policy.SecurityIDContexts) {
	for identity, ruleContexts := range newSecIDs {
		for ruleContext, v := range ruleContexts {
			if _, ok := secIDs[identity]; !ok {
				secIDs[identity] = policy.NewL4RuleContexts()
			}
			e, ok := secIDs[identity][ruleContext]
			v.L4Installed = (v.L4Installed && !ok) || (v.L4Installed && e.L4Installed)
			secIDs[identity][ruleContext] = v
		}
	}
}

// Looks for mismatches between 'oldPolicy' and 'newPolicy', and fixes up
// this Endpoint's BPF PolicyMap to reflect the new L3+L4 combined policy.
// Returns a map that represents all L3-dependent L4 rules that were attempted
// to be added;
// and a map that represents all L3-dependent L4 rules that were attempted
// to be removed;
// it maps to whether they were removed successfully (true or false)
func (e *Endpoint) applyL4PolicyLocked(owner Owner, labelsMap *policy.IdentityCache,
	oldPolicy, newPolicy *policy.L4Policy) (secIDsAdd, secIDsRm policy.SecurityIDContexts, err error) {

	secIDsAdd = policy.NewSecurityIDContexts()
	secIDsRm = policy.NewSecurityIDContexts()

	if oldPolicy != nil {
		var secIDs policy.SecurityIDContexts
		for _, filter := range oldPolicy.Ingress {
			secIDs = e.removeOldFilter(owner, labelsMap, &filter)
			setMapOperationResult(secIDsRm, secIDs)
		}
	}

	if newPolicy == nil {
		return secIDsAdd, secIDsRm, nil
	}

	var (
		errors, errs = 0, 0
		secIDs       policy.SecurityIDContexts
	)
	for _, filter := range newPolicy.Ingress {
		secIDs, errs = e.applyNewFilter(owner, labelsMap, &filter)
		setMapOperationResult(secIDsAdd, secIDs)
		errors += errs
	}

	if errors > 0 {
		return secIDsAdd, secIDsRm, fmt.Errorf("Some Label+L4 policy updates failed.")
	}
	return secIDsAdd, secIDsRm, nil
}

func getLabelsMap() (*policy.IdentityCache, error) {
	labelsMap := policy.GetIdentityCache()

	reservedIDs := policy.GetConsumableCache().GetReservedIDs()
	var idx policy.NumericIdentity
	for _, idx = range reservedIDs {
		lbls := policy.ResolveIdentityLabels(idx)
		if lbls == nil || len(lbls) == 0 {
			return nil, fmt.Errorf("unable to resolve reserved identity")
		}
		labelsMap[idx] = lbls
	}

	return &labelsMap, nil
}

// Must be called with global endpoint.Mutex held
func (e *Endpoint) resolveL4Policy(owner Owner, repo *policy.Repository, c *policy.Consumable) error {
	ctx := policy.SearchContext{
		To: c.LabelArray,
	}
	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}

	newL4Policy, err := repo.ResolveL4Policy(&ctx)
	if err != nil {
		return err
	}

	if reflect.DeepEqual(c.L4Policy, newL4Policy) {
		return nil
	}

	c.L4Policy = newL4Policy
	return nil
}

// Must be called with global endpoint.Mutex held
// Returns a boolean to signalize if the policy was changed;
// and a map matching which rules were successfully added/modified;
// and a map matching which rules were successfully removed.
func (e *Endpoint) regenerateConsumable(owner Owner, labelsMap *policy.IdentityCache,
	repo *policy.Repository, c *policy.Consumable) (changed bool, rulesAdd policy.SecurityIDContexts, rulesRm policy.SecurityIDContexts) {

	var (
		l4Rm policy.SecurityIDContexts
		err  error
	)

	// Mark all entries unused by denying them
	for k := range c.Consumers {
		c.Consumers[k].DeletionMark = true
	}

	rulesAdd = policy.NewSecurityIDContexts()
	rulesRm = policy.NewSecurityIDContexts()

	// L4 policy needs to be applied on two conditions
	// 1. The L4 policy has changed
	// 2. The set of applicable security identities has changed.
	if e.L4Policy == c.L4Policy && e.LabelsMap == labelsMap {
		// If there were no modifications to the L3-L4, copy the existing L3-L4
		// policy.
		if c.L3L4Policy != nil {
			rulesAdd = *c.L3L4Policy
		}
	} else {
		changed = true

		// PolicyMap can't be created in dry mode.
		if !owner.DryModeEnabled() {
			// Collect unused redirects.
			if e.L4Policy != nil {
				e.collectUnusedRedirects(e.L4Policy.Ingress, c.L4Policy.Ingress)
				e.collectUnusedRedirects(e.L4Policy.Egress, c.L4Policy.Egress)
			}
			rulesAdd, l4Rm, err = e.applyL4PolicyLocked(owner, labelsMap, e.L4Policy, c.L4Policy)
			if err != nil {
				// This should not happen, and we can't fail at this stage anyway.
				e.getLogger().WithError(err).Fatal("L4 Policy application failed")
			}
		}
		// Reuse the common policy, will be used in lxc_config.h (CFG_L4_INGRESS and CFG_L4_EGRESS)
		e.L4Policy = c.L4Policy
		e.LabelsMap = labelsMap // Remember the set of labels used

		// We need to know which rules are L4-only by checking
		// if there are any L4-only rules that do not match a L3-L4 rule.
		if c != nil && c.L4Policy != nil && c.L4Policy.Ingress != nil {
			for _, l4Filter := range c.L4Policy.Ingress {
				found := false
				l4RuleCtx, l7RuleCtx := policy.ParseL4Filter(l4Filter)
				for _, l4RuleContexts := range rulesAdd {
					if _, found = l4RuleContexts[l4RuleCtx]; found {
						break
					}
				}
				if !found {
					if _, ok := rulesAdd[policy.InvalidIdentity]; !ok {
						rulesAdd[policy.InvalidIdentity] = policy.NewL4RuleContexts()
					}
					l7RuleCtx.L4Installed = true
					rulesAdd[policy.InvalidIdentity][l4RuleCtx] = l7RuleCtx
				}
			}
		}

		// Only remove the CT entries of the rules that were successfully
		// removed (added to l4Rm) and not successfully re-added (added to rulesAdd)
		for secID, ruleCtxsRm := range l4Rm {
			if addL4RuleCtxs, ok := rulesAdd[secID]; ok {
				for addl4RuleCtx, addl7RuleCtx := range addL4RuleCtxs {
					rm, ok := ruleCtxsRm[addl4RuleCtx]
					if rm.L4Installed && ok && !(addl7RuleCtx.L4Installed) {
						if _, ok := rulesRm[secID]; !ok {
							rulesRm[secID] = policy.NewL4RuleContexts()
						}
						rulesRm[secID][addl4RuleCtx] = addl7RuleCtx
					}
				}
			} else {
				// If the L3 rule was not re-added then we clean up all CT
				// entries only based on L3.
				if _, ok := rulesRm[secID]; !ok {
					rulesRm[secID] = policy.NewL4RuleContexts()
				}
				for rmL4RuleCtx, rmL7RuleCtx := range ruleCtxsRm {
					removed, ok := rulesRm[secID][rmL4RuleCtx]
					rmL7RuleCtx.L4Installed = rmL7RuleCtx.L4Installed || (removed.L4Installed && ok)
					rulesRm[secID][rmL4RuleCtx] = rmL7RuleCtx
				}
			}
		}
	}

	if owner.AlwaysAllowLocalhost() || c.L4Policy.HasRedirect() {
		if e.allowConsumer(owner, policy.ReservedIdentityHost) {
			changed = true
		}
	}

	ctx := policy.SearchContext{
		To: c.LabelArray,
	}
	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}

	for srcID, srcLabels := range *labelsMap {
		ctx.From = srcLabels
		e.getLogger().WithFields(logrus.Fields{
			logfields.PolicyID: srcID,
			"ctx":              ctx,
		}).Debug("Evaluating context for source PolicyID")

		if repo.AllowsLabelAccess(&ctx) == api.Allowed {
			if e.allowConsumer(owner, srcID) {
				changed = true
			}
		}
	}

	// Garbage collect all unused entries
	for _, val := range c.Consumers {
		if val.DeletionMark {
			val.DeletionMark = false
			c.BanConsumerLocked(val.ID)
			changed = true
			// Since we have removed a consumer, the L3 rule should be
			// also be marked as removed. But only if it was not previously
			// created by a L3-L4 rule.
			if _, ok := rulesRm[val.ID]; !ok {
				rulesRm[val.ID] = policy.NewL4RuleContexts()
			}
			// If the L3 rule was removed then we also need to remove it from
			// the rulesAdded.
			if _, ok := rulesAdd[val.ID]; ok {
				delete(rulesAdd, val.ID)
			}
		} else {
			// Since we have (re)added a consumer, the L3 rule should be
			// also be marked as added. But only if it was not previously
			// created by a L3-L4 rule.
			if _, ok := rulesAdd[val.ID]; !ok {
				rulesAdd[val.ID] = policy.NewL4RuleContexts()
			}
		}
	}

	if rulesAdd != nil {
		rulesAddCpy := rulesAdd.DeepCopy() // Store the L3-L4 policy
		c.L3L4Policy = &rulesAddCpy
	}

	e.getLogger().WithFields(logrus.Fields{
		logfields.Identity: c.ID,
		"consumers":        logfields.Repr(c.Consumers),
		"rulesAdd":         rulesAdd,
		"l4Rm":             l4Rm,
		"rulesRm":          rulesRm,
	}).Debug("New consumable with consumers")
	return changed, rulesAdd, rulesRm
}

// Must be called with global repo.Mutrex, e.Mutex, and c.Mutex held
func (e *Endpoint) regenerateL3Policy(owner Owner, repo *policy.Repository, revision uint64, c *policy.Consumable) (bool, error) {

	ctx := policy.SearchContext{
		To: c.LabelArray, // keep c.Mutex taken to protect this.
	}
	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}
	newL3policy := repo.ResolveCIDRPolicy(&ctx)
	// Perform the validation on the new policy
	err := newL3policy.Validate()
	valid := err == nil

	if valid {
		if reflect.DeepEqual(e.L3Policy, newL3policy) {
			e.getLogger().Debug("No change in CIDR policy")
			return false, nil
		}
		e.L3Policy = newL3policy
	}

	return valid, err
}

// IngressOrEgressIsEnforced returns true if either ingress or egress is in
// enforcement mode or if the global policy enforcement is enabled.
func (e *Endpoint) IngressOrEgressIsEnforced() bool {
	return policy.GetPolicyEnabled() == AlwaysEnforce ||
		e.Opts.IsEnabled(OptionIngressPolicy) ||
		e.Opts.IsEnabled(OptionEgressPolicy)
}

// regeneratePolicy regenerates endpoint's policy if needed and returns
// whether the BPF for the given endpoint should be regenerated. Only
// called when e.Consumable != nil.
//
// In a typical workflow this is first called to regenerate the policy
// (if needed), and second time when the BPF program is
// regenerated. The second step is usually unnecessary and may be
// optimized away by the revision checks.  However, if there has been
// a further policy update between the first and second calls, the
// second call will update the policy just before regenerating the BPF
// programs to avoid needing to regenerate BPF programs aging right
// after.
//
// Policy changes are tracked so that only endpoints affected by the
// policy change need to have their BPF programs regenerated.
//
// Policy generation may fail, and in that case we exit before
// actually changing the policy in any way, so that the last policy
// remains fully in effect if the new policy can not be
// implemented. This is done on a per endpoint-basis, however, and it is
// possible that policy update succeeds for some endpoints, while it
// fails for other endpoints.
//
// Returns:
//  - changed: true if the policy was changed for this endpoint;
//  - consumersAdded: map of SecurityIDContexts that contains a map of rule
// 					  contexts that were added to the L4 policy map;
//  - consumersRemoved: map of SecurityIDContexts that contains a map of rule
// 					    contexts that were removed from the L4 policy map;
//  - err: error in case of an error.
// Must be called with endpoint mutex held.
func (e *Endpoint) regeneratePolicy(owner Owner, opts models.ConfigurationMap) (bool, policy.SecurityIDContexts, policy.SecurityIDContexts, error) {
	// Dry mode does not regenerate policy via bpf regeneration, so we let it pass
	// through. Some bpf/redirect updates are skipped in that case.
	//
	// This can be cleaned up once we shift all bpf updates to regenerateBPF().
	if e.PolicyMap == nil && !owner.DryModeEnabled() {
		// First run always results in bpf generation
		// L4 policy generation assumes e.PolicyMp to exist, but it is only created
		// when bpf is generated for the first time. Until then we can't really compute
		// the policy. Bpf generation calls us again after PolicyMap is created.
		// In dry mode we are called with a nil PolicyMap.

		// We still need to apply any options if given.
		if opts != nil {
			e.applyOptsLocked(opts)
		}

		return true, nil, nil, nil
	}

	e.getLogger().Debug("Starting regenerate...")

	// Collect label arrays before policy computation, as this can fail.
	// GH-1128 should allow optimizing this away, but currently we can't
	// reliably know if the KV-store has changed or not, so we must scan
	// through it each time.
	labelsMap, err := getLabelsMap()
	if err != nil {
		e.getLogger().WithError(err).Debug("Received error while evaluating policy")
		return false, nil, nil, err
	}
	if reflect.DeepEqual(e.LabelsMap, labelsMap) {
		labelsMap = e.LabelsMap
	}

	repo := owner.GetPolicyRepository()
	repo.Mutex.RLock()
	revision := repo.GetRevision()
	defer repo.Mutex.RUnlock()

	// Recompute policy for this endpoint only if not already done for this revision.
	if !e.forcePolicyCompute && e.nextPolicyRevision >= revision &&
		labelsMap == e.LabelsMap && opts == nil {

		e.getLogger().WithFields(logrus.Fields{
			"policyRevision.next": e.nextPolicyRevision,
			"policyRevision.repo": revision,
		}).Debug("Skipping policy recalculation")
		// This revision already computed, but may still need to be applied to BPF
		return e.nextPolicyRevision > e.policyRevision, nil, nil, nil
	}

	if opts == nil {
		opts = make(models.ConfigurationMap)
	}

	c := e.Consumable

	// We may update the consumable, serialize access between endpoints sharing it
	c.Mutex.Lock()
	defer c.Mutex.Unlock()

	// Containers without a security label are not accessible
	if c.ID == 0 {
		e.getLogger().Warn("Endpoint lacks identity, skipping policy calculation")
		return false, nil, nil, nil
	}

	// Skip L4 policy recomputation for this consumable if already valid.
	// Rest of the policy computation still needs to be done for each endpoint
	// separately even thought the consumable may be shared between them.
	if c.Iteration != revision {
		err = e.resolveL4Policy(owner, repo, c)
		if err != nil {
			return false, nil, nil, err
		}
		// Result is valid until cache iteration advances
		c.Iteration = revision
	} else {
		e.getLogger().WithField(logfields.Identity, c.ID).Debug("Reusing cached L4 policy")
	}

	var policyChanged bool
	if policyChanged, err = e.regenerateL3Policy(owner, repo, revision, c); err != nil {
		return false, nil, nil, err
	}

	// no failures after this point

	// Apply possible option changes before regenerating maps, as map regeneration
	// depends on the conntrack options
	if c.L4Policy != nil {
		if c.L4Policy.RequiresConntrack() {
			opts[OptionConntrack] = optionEnabled
		}
	}

	ingress, egress := owner.EnableEndpointPolicyEnforcement(e)

	opts[OptionIngressPolicy] = optionDisabled
	opts[OptionEgressPolicy] = optionDisabled

	if egress {
		e.checkEgressAccess(owner, (*labelsMap)[policy.ReservedIdentityHost], opts, OptionAllowToHost)
	}

	if !ingress && !egress {
		e.getLogger().Debug("Policy Ingress and Egress disabled")
	} else {
		if ingress && egress {
			e.getLogger().Debug("Policy Ingress and Egress enabled")
			opts[OptionIngressPolicy] = optionEnabled
			opts[OptionEgressPolicy] = optionEnabled
		} else if ingress {
			e.getLogger().Debug("Policy Ingress enabled")
			opts[OptionIngressPolicy] = optionEnabled
		} else {
			e.getLogger().Debug("Policy Egress enabled")
			opts[OptionEgressPolicy] = optionEnabled
		}
	}

	optsChanged := e.applyOptsLocked(opts)

	policyChanged2, consumersAdd, consumersRm := e.regenerateConsumable(owner, labelsMap, repo, c)
	if policyChanged2 {
		policyChanged = true
	}

	// If we are in this function, then policy has been calculated.
	if !e.PolicyCalculated {
		e.getLogger().Debug("setting PolicyCalculated to true for endpoint")
		e.PolicyCalculated = true
		// Always trigger a regenerate after the first policy
		// calculation has been performed
		optsChanged = true
	}

	if e.forcePolicyCompute {
		optsChanged = true           // Options were changed by the caller.
		e.forcePolicyCompute = false // Policies just computed
		e.getLogger().Debug("Forced policy recalculation")
	}

	e.nextPolicyRevision = revision

	// If no policy or options change occurred for this endpoint then the endpoint is
	// already running the latest revision, otherwise we have to wait for
	// the regeneration of the endpoint to complete.
	if !policyChanged && !optsChanged {
		e.policyRevision = revision
	}

	e.getLogger().WithFields(logrus.Fields{
		"policyChanged":       policyChanged,
		"optsChanged":         optsChanged,
		"policyRevision.next": e.nextPolicyRevision,
	}).Debug("Done regenerating")

	// Return true if need to regenerate BPF
	return optsChanged || policyChanged || e.nextPolicyRevision > e.policyRevision, consumersAdd, consumersRm, nil
}

// Called with e.Mutex UNlocked
func (e *Endpoint) regenerate(owner Owner, reason string) (retErr error) {
	metrics.EndpointCountRegenerating.Inc()
	defer func() {
		metrics.EndpointCountRegenerating.Dec()
		if retErr == nil {
			metrics.EndpointRegenerationCount.
				WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
		} else {
			metrics.EndpointRegenerationCount.
				WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		}
	}()

	e.BuildMutex.Lock()
	defer e.BuildMutex.Unlock()

	e.Mutex.RLock()
	e.getLogger().Debug("Regenerating endpoint...")
	e.Mutex.RUnlock()

	origDir := filepath.Join(owner.GetStateDir(), e.StringID())

	// This is the temporary directory to store the generated headers,
	// the original existing directory is not overwritten until the
	// entire generation process has succeeded.
	tmpDir := origDir + "_next"

	// Create temporary endpoint directory if it does not exist yet
	if err := os.MkdirAll(tmpDir, 0777); err != nil {
		return fmt.Errorf("Failed to create endpoint directory: %s", err)
	}

	defer func() {
		// Set to Ready, but only if no other changes are pending.
		// State will remain as waiting-to-regenerate if further
		// changes are needed. There should be an another regenerate
		// queued for taking care of it.
		e.Mutex.Lock()
		e.BuilderSetStateLocked(StateReady, "Completed endpoint regeneration with no pending regeneration requests")
		e.Mutex.Unlock()
	}()

	revision, err := e.regenerateBPF(owner, tmpDir, reason)
	if err != nil {
		os.RemoveAll(tmpDir)
		return err
	}

	// Move the current endpoint directory to a backup location
	backupDir := origDir + "_stale"
	if err := os.Rename(origDir, backupDir); err != nil {
		os.RemoveAll(tmpDir)
		return fmt.Errorf("Unable to rename current endpoint directory: %s", err)
	}

	// Make temporary directory the new endpoint directory
	if err := os.Rename(tmpDir, origDir); err != nil {
		os.RemoveAll(tmpDir)

		if err2 := os.Rename(backupDir, origDir); err2 != nil {
			e.getLogger().WithFields(logrus.Fields{
				logfields.Path: backupDir,
			}).Warn("Restoring directory for endpoint failed, endpoint " +
				"is in inconsistent state. Keeping stale directory.")
			return err2
		}

		return fmt.Errorf("Restored original endpoint directory, atomic replace failed: %s", err)
	}

	os.RemoveAll(backupDir)

	// Mark the endpoint to be running the policy revision it was
	// compiled for
	e.bumpPolicyRevision(revision)

	e.getLogger().Info("Endpoint policy recalculated")

	return nil
}

// Regenerate forces the regeneration of endpoint programs & policy
// Should only be called with e.state == StateWaitingToRegenerate
func (e *Endpoint) Regenerate(owner Owner, reason string) <-chan bool {
	newReq := &Request{
		ID:           uint64(e.ID),
		MyTurn:       make(chan bool),
		Done:         make(chan bool),
		ExternalDone: make(chan bool),
	}

	go func(owner Owner, req *Request, e *Endpoint) {
		buildSuccess := true

		e.Mutex.Lock()
		// This must be accessed in a locked section, so we grab it here.
		scopedLog := e.getLogger()
		e.Mutex.Unlock()

		// We should only queue the request after we use all the endpoint's
		// lock/unlock. Otherwise this can get a deadlock if the endpoint is
		// being deleted at the same time. More info PR-1777.
		owner.QueueEndpointBuild(req)

		isMyTurn, isMyTurnChanOK := <-req.MyTurn
		if isMyTurnChanOK && isMyTurn {
			scopedLog.Debug("Dequeued endpoint from build queue")

			if err := e.regenerate(owner, reason); err != nil {
				buildSuccess = false
				scopedLog.WithError(err).Warn("Regeneration of endpoint program failed")
				e.LogStatus(BPF, Failure, "Error regenerating endpoint: "+err.Error())
				owner.SendNotification(monitor.AgentNotifyEndpointRegenerateFail,
					e.getIDandLabels()+": "+err.Error())
			} else {
				buildSuccess = true
				e.LogStatusOK(BPF, "Successfully regenerated endpoint program due to "+reason)
				owner.SendNotification(monitor.AgentNotifyEndpointRegenerateSuccess, e.getIDandLabels())
			}

			req.Done <- buildSuccess
		} else {
			buildSuccess = false

			scopedLog.Debug("My request was cancelled because I'm already in line")
		}
		// The external listener can ignore the channel so we need to
		// make sure we don't block
		select {
		case req.ExternalDone <- buildSuccess:
		default:
		}
		close(req.ExternalDone)
	}(owner, newReq, e)
	return newReq.ExternalDone
}

// TriggerPolicyUpdatesLocked indicates that a policy change is likely to
// affect this endpoint. Will update all required endpoint configuration and
// state to reflect new policy.
//
// Returns true if policy was changed and the endpoint needs to be rebuilt
func (e *Endpoint) TriggerPolicyUpdatesLocked(owner Owner, opts models.ConfigurationMap) (bool, *sync.WaitGroup, error) {
	ctCleaned := &sync.WaitGroup{}

	if e.Consumable == nil {
		return false, ctCleaned, nil
	}

	changed, consumersAdd, consumersRm, err := e.regeneratePolicy(owner, opts)
	if err != nil {
		return false, ctCleaned, fmt.Errorf("%s: %s", e.StringID(), err)
	}

	if changed && consumersAdd != nil {
		policyEnforced := e.IngressOrEgressIsEnforced()
		isLocal := e.Opts.IsEnabled(OptionConntrackLocal)
		epIPs := []net.IP{e.IPv4.IP(), e.IPv6.IP()}
		ctCleaned = updateCT(owner, e, epIPs, policyEnforced, isLocal, consumersAdd, consumersRm)
	}

	e.getLogger().Debugf("TriggerPolicyUpdatesLocked: changed: %t", changed)

	return changed, ctCleaned, nil
}

func (e *Endpoint) runIdentityToK8sPodSync() {
	e.controllers.UpdateController(fmt.Sprintf("sync-identity-to-k8s-pod (%d)", e.ID),
		controller.ControllerParams{
			DoFunc: func() error {
				id := ""

				e.Mutex.RLock()
				if e.SecLabel != nil {
					id = e.SecLabel.ID.String()
				}
				e.Mutex.RUnlock()

				if id != "" && e.GetK8sNamespace() != "" && e.GetK8sPodName() != "" {
					return k8s.AnnotatePod(e, common.CiliumIdentityAnnotation, id)
				}

				return nil
			},
			RunInterval: time.Duration(1) * time.Minute,
		},
	)
}

// SetIdentity resets endpoint's policy identity to 'id'.
// Caller triggers policy regeneration if needed.
// Called with e.Mutex Locked
func (e *Endpoint) SetIdentity(owner Owner, id *policy.Identity) {
	cache := policy.GetConsumableCache()

	if e.Consumable != nil {
		if e.SecLabel != nil && id.ID == e.Consumable.ID {
			// Even if the numeric identity is the same, the order in which the
			// labels are represented may change.
			e.SecLabel = id
			e.Consumable.Mutex.Lock()
			e.Consumable.Labels = id
			e.Consumable.LabelArray = id.Labels.ToSlice()
			e.Consumable.Mutex.Unlock()
			return
		}
		// TODO: This removes the consumable from the cache even if other endpoints
		// would still point to it. Consumable should be removed from the cache
		// only when no endpoint refers to it. Fix by implementing explicit reference
		// counting via the cache?
		cache.Remove(e.Consumable)
	}
	e.SecLabel = id
	e.Consumable = cache.GetOrCreate(id.ID, id)

	// Sets endpoint state to ready if was waiting for identity
	if e.GetStateLocked() == StateWaitingForIdentity {
		e.SetStateLocked(StateReady, "Set identity for this endpoint")
	}

	e.runIdentityToK8sPodSync()

	e.Consumable.Mutex.RLock()
	e.getLogger().WithFields(logrus.Fields{
		logfields.Identity: id,
		"consumable":       e.Consumable,
	}).Debug("Set identity and consumable of EP")
	e.Consumable.Mutex.RUnlock()
}
