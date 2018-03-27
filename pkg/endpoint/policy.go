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
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/controller"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/node"
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

	switch owner.GetPolicyRepository().AllowsIngressLabelAccess(&ctx) {
	case api.Allowed:
		opts[opt] = optionEnabled
		scopedLog.Debug("checkEgressAccess: Enabled")
	case api.Denied:
		opts[opt] = optionDisabled
		scopedLog.Debug("checkEgressAccess: Disabled")
	}
}

// allowIngressIdentity must be called with global endpoint.Mutex held
func (e *Endpoint) allowIngressIdentity(id identityPkg.NumericIdentity) bool {
	return e.Consumable.AllowIngressIdentityLocked(policy.GetConsumableCache(), id)
}

// allowEgressIdentity allows security identity id to be communicated to by
// this endpoint by updating the endpoint's Consumable.
// Must be called with global endpoint.Mutex held.
func (e *Endpoint) allowEgressIdentity(id identityPkg.NumericIdentity) bool {
	cache := policy.GetConsumableCache()
	return e.Consumable.AllowEgressIdentityLocked(cache, id)
}

// ProxyID returns a unique string to identify a proxy mapping.
func (e *Endpoint) ProxyID(l4 *policy.L4Filter) string {
	return policy.ProxyID(e.ID, l4.Ingress, string(l4.Protocol), uint16(l4.Port))
}

func getSecurityIdentities(labelsMap *identityPkg.IdentityCache, selector *api.EndpointSelector) []identityPkg.NumericIdentity {
	identities := []identityPkg.NumericIdentity{}
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

func getL4FilterEndpointSelector(filter *policy.L4Filter) []api.EndpointSelector {
	// Since GH-3015 it's impossible to specify more than one L3 at a time,
	// and the only L3 rule match that is allowed to be combined with L4
	// is `FromEndpoints`. Therefore, if `FromEndpoints` is nil, then it
	// selects all endpoints - so we can use a wildcard selector here.
	// When additional L3-dependent L4 rules are supported, this logic
	// will need to be amended to only wildcard endpoints when no L3 is
	// specified. See also GH-2992 for context.
	// TODO (ianvernon) - look into this.
	fromEndpointsSelectors := filter.Endpoints
	if fromEndpointsSelectors == nil {
		fromEndpointsSelectors = []api.EndpointSelector{
			api.NewWildcardEndpointSelector(),
		}
	}

	return fromEndpointsSelectors
}

// removeOldL4Filter removes the BPF map entries from the endpoint's PolicyMap which
// corresponds to the given L4Filter in the given direction.
// Returns a map that represents all values from the endpoint's PolicyMap that
// were attempted to be removed.
func (e *Endpoint) removeOldL4Filter(labelsMap *identityPkg.IdentityCache,
	filter *policy.L4Filter, direction policymap.TrafficDirection) policy.SecurityIdentityL4L7Map {

	attemptedRemovedMapEntries := policy.NewSecurityIdentityL4L7Map()
	port := uint16(filter.Port)
	proto := uint8(filter.U8Proto)

	// Get endpoint selectors which correspond to L4Filter.
	for _, sel := range getL4FilterEndpointSelector(filter) {
		// Get all identities which correspond to this endpoint selector and
		// delete them from the BPF PolicyMap for this endpoint.
		for _, securityIdentity := range getSecurityIdentities(labelsMap, &sel) {
			srcID := securityIdentity.Uint32()

			// Convert filter to in-memory representation which is used for
			// conntrack cleanup. Since we are removing entries from the BPF
			// datapath, we need to keep track of which entries were removed
			// (and attempted to be removed) so we can clear the conntrack table
			// of entries for which policy no longer allows traffic after policy
			// is realized for this endpoint.
			l4Metadata, l7Metadata := e.ParseL4Filter(filter)
			if _, ok := attemptedRemovedMapEntries[securityIdentity]; !ok {
				attemptedRemovedMapEntries[securityIdentity] = policy.NewL4L7Map()
			}
			if err := e.PolicyMap.DeleteL4(srcID, port, proto, direction); err != nil {
				// This happens when the policy would add
				// multiple copies of the same L4 policy. Only
				// one of them is actually added, but we'll
				// still try to remove it multiple times.
				e.getLogger().WithError(err).WithField(logfields.L4PolicyID, srcID).
					Debug("deletion of old L4 policy failed")
				// Set with false only if the key was not
				// previously set nor the value was set
				// with true. Since we can have multiple
				// copies of the same L4 policy, a single
				// successful DeleteL4 means the policy
				// was actually removed.
				v, ok := attemptedRemovedMapEntries[securityIdentity][l4Metadata]
				if ok && !v.L4Installed {
					attemptedRemovedMapEntries[securityIdentity][l4Metadata] = l7Metadata
				}
			} else {
				// Rule was successfully deleted.
				// TODO (ianvernon) why is this value set to 'true' if the entry is
				// no longer in the map?
				l7Metadata.L4Installed = true
				attemptedRemovedMapEntries[securityIdentity][l4Metadata] = l7Metadata
			}
		}
	}

	return attemptedRemovedMapEntries
}

// applyNewFilter adds the given l4 filter to the endpoint.
// Returns a map that represents all policies that were attempted to be added;
// it maps to whether they were added successfully (true or false).
// It also returns the number of errors that occurred while when applying the
// policy.
// Applies for L3 dependent L4 not for L4-only.
func (e *Endpoint) applyNewFilter(labelsMap *identityPkg.IdentityCache,
	filter *policy.L4Filter, direction policymap.TrafficDirection) (policy.SecurityIdentityL4L7Map, int) {

	attemptedAddedMapEntries := policy.NewSecurityIdentityL4L7Map()
	port := uint16(filter.Port)
	proto := uint8(filter.U8Proto)

	errors := 0
	for _, sel := range getL4FilterEndpointSelector(filter) {
		for _, id := range getSecurityIdentities(labelsMap, &sel) {
			srcID := id.Uint32()
			if e.PolicyMap.L4Exists(srcID, port, proto, direction) {
				e.getLogger().WithField("l4Filter", filter).Debug("L4 filter exists")
				continue
			}
			l4RuleCtx, l7RuleCtx := e.ParseL4Filter(filter)
			if _, ok := attemptedAddedMapEntries[id]; !ok {
				attemptedAddedMapEntries[id] = policy.NewL4L7Map()
			}
			if err := e.PolicyMap.AllowL4(srcID, port, proto, direction); err != nil {
				e.getLogger().WithFields(logrus.Fields{
					logfields.PolicyID:         srcID,
					logfields.Port:             port,
					logfields.Protocol:         proto,
					logfields.TrafficDirection: direction}).WithError(err).Warn(
					"Update of l4 policy map failed")
				errors++
				l7RuleCtx.L4Installed = false
				attemptedAddedMapEntries[id][l4RuleCtx] = l7RuleCtx
			} else {
				l7RuleCtx.L4Installed = true
				attemptedAddedMapEntries[id][l4RuleCtx] = l7RuleCtx
			}
		}
	}
	return attemptedAddedMapEntries, errors
}

// setMapOperationResult iterates over the newSecIDs and sets their result
// to the secIDs map only when either:
//  - It is the first time an assignment is being done to this
//    key and the value is true OR
//  - The previous assigned value and the new value are both
//    true
func setMapOperationResult(secIDs, newSecIDs policy.SecurityIdentityL4L7Map) {
	for identity, ruleContexts := range newSecIDs {
		for ruleContext, v := range ruleContexts {
			if _, ok := secIDs[identity]; !ok {
				secIDs[identity] = policy.NewL4L7Map()
			}
			l7Metadata, ok := secIDs[identity][ruleContext]
			v.L4Installed = (v.L4Installed && !ok) || (v.L4Installed && l7Metadata.L4Installed)
			secIDs[identity][ruleContext] = v
		}
	}
}

// Looks for mismatches between 'oldPolicy' and 'newPolicy', and fixes up
// this Endpoint's BPF PolicyMap to reflect the new L3+L4 combined policy.
// Returns a map that represents all L3-dependent L4 rules that were attempted
// to be added;
// and a map that represents all L3-dependent L4 rules that were attempted
// to be removed.
func (e *Endpoint) applyL4PolicyLocked(labelsMap *identityPkg.IdentityCache,
	oldPolicy, newPolicy *policy.L4Policy, direction policymap.TrafficDirection) (allAddedEntries, allRemovedEntries policy.SecurityIdentityL4L7Map, err error) {

	allAddedEntries = policy.NewSecurityIdentityL4L7Map()
	allRemovedEntries = policy.NewSecurityIdentityL4L7Map()

	var oldL4PolicyMap policy.L4PolicyMap
	var newL4PolicyMap policy.L4PolicyMap

	switch direction {
	case policymap.Ingress:
		oldL4PolicyMap = oldPolicy.Ingress
		newL4PolicyMap = newPolicy.Ingress
	case policymap.Egress:
		oldL4PolicyMap = oldPolicy.Egress
		newL4PolicyMap = newPolicy.Egress
	}

	// Remove all old filters.
	if oldPolicy != nil {
		var attemptedRemovedPolicyMapEntries policy.SecurityIdentityL4L7Map
		for _, filter := range oldL4PolicyMap {
			attemptedRemovedPolicyMapEntries = e.removeOldL4Filter(labelsMap, &filter, direction)
			setMapOperationResult(allRemovedEntries, attemptedRemovedPolicyMapEntries)
		}
	}

	if newPolicy == nil {
		return allAddedEntries, allRemovedEntries, nil
	}

	var errors = 0

	// Add new filters.
	for _, filter := range newL4PolicyMap {
		attemptedAddedPolicyMapEntries, errs := e.applyNewFilter(labelsMap, &filter, direction)
		setMapOperationResult(allAddedEntries, attemptedAddedPolicyMapEntries)
		errors += errs
	}

	if errors > 0 {
		return allAddedEntries, allRemovedEntries, fmt.Errorf("Some Label+L4 policy updates failed.")
	}
	return allAddedEntries, allRemovedEntries, nil
}

func getLabelsMap() (*identityPkg.IdentityCache, error) {
	labelsMap := identityPkg.GetIdentityCache()

	reservedIDs := policy.GetConsumableCache().GetReservedIDs()
	var idx identityPkg.NumericIdentity
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

	ingressCtx := policy.SearchContext{
		To: c.LabelArray,
	}

	egressCtx := policy.SearchContext{
		From: c.LabelArray,
	}

	if owner.TracingEnabled() {
		ingressCtx.Trace = policy.TRACE_ENABLED
		egressCtx.Trace = policy.TRACE_ENABLED
	}

	newL4IngressPolicy, err := repo.ResolveL4IngressPolicy(&ingressCtx)
	if err != nil {
		return err
	}

	newL4EgressPolicy, err := repo.ResolveL4EgressPolicy(&egressCtx)
	if err != nil {
		return err
	}

	newL4Policy := &policy.L4Policy{Ingress: *newL4IngressPolicy,
		Egress: *newL4EgressPolicy}

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
// Must be called with Consumable mutex held.
func (e *Endpoint) regenerateConsumable(owner Owner, labelsMap *identityPkg.IdentityCache,
	repo *policy.Repository, c *policy.Consumable) (changed bool, ingressRulesAdd, ingressRulesRm policy.SecurityIdentityL4L7Map, err error) {

	var (
		ingressL4ToRemove policy.SecurityIdentityL4L7Map
		egressL4ToRemove  policy.SecurityIdentityL4L7Map
	)

	// Mark all entries unused by denying them
	for ingressIdentity := range c.IngressIdentities {
		// Mark as false indicates denying
		c.IngressIdentities[ingressIdentity] = false
	}

	for egressIdentity := range c.EgressIdentities {
		c.EgressIdentities[egressIdentity] = false
	}

	ingressRulesAdd = policy.NewSecurityIdentityL4L7Map()
	ingressRulesRm = policy.NewSecurityIdentityL4L7Map()

	egressRulesAdd := policy.NewSecurityIdentityL4L7Map()
	egressRulesRm := policy.NewSecurityIdentityL4L7Map()

	// L4 policy needs to be applied on two conditions
	// 1. The L4 policy has changed
	// 2. The set of applicable security identities has changed.
	if e.L4Policy == c.L4Policy && e.LabelsMap == labelsMap {
		// If there were no modifications to the L3-L4, copy the existing L3-L4
		// policy.
		if c.L3L4Policy != nil {
			ingressRulesAdd = *c.L3L4Policy
			egressRulesAdd = *c.L3L4Policy

		}
	} else {
		changed = true

		// PolicyMap can't be created in dry mode.
		if !owner.DryModeEnabled() {
			// Collect unused redirects.
			ingressRulesAdd, ingressL4ToRemove, err = e.applyL4PolicyLocked(labelsMap, e.L4Policy, c.L4Policy, policymap.Ingress)
			if err != nil {
				// This should not happen, and we can't fail at this stage anyway.
				e.getLogger().WithError(err).Fatal("Ingress L4 Policy application failed")
			}

			// Collect unused redirects.
			egressRulesAdd, egressL4ToRemove, err = e.applyL4PolicyLocked(labelsMap, e.L4Policy, c.L4Policy, policymap.Egress)
			if err != nil {
				// This should not happen, and we can't fail at this stage anyway.
				e.getLogger().WithError(err).Error("Ingress L4 Policy application failed")
				return
			}
		}
		// Reuse the common policy, will be used in lxc_config.h (CFG_L4_INGRESS and CFG_L4_EGRESS)
		e.L4Policy = c.L4Policy
		e.LabelsMap = labelsMap // Remember the set of labels used

		// We need to know which rules are L4-only by checking
		// if there are any L4-only rules that do not match a L3-L4 rule.
		if c != nil && c.L4Policy != nil {
			for _, l4Filter := range c.L4Policy.Ingress {
				found := false
				l4Rule, l7Rule := e.ParseL4Filter(&l4Filter)
				for _, ruleL4IngressMetadata := range ingressRulesAdd {
					if _, found = ruleL4IngressMetadata[l4Rule]; found {
						break
					}
				}
				if !found {
					if _, ok := ingressRulesAdd[identityPkg.InvalidIdentity]; !ok {
						ingressRulesAdd[identityPkg.InvalidIdentity] = policy.NewL4L7Map()
					}
					l7Rule.L4Installed = true
					ingressRulesAdd[identityPkg.InvalidIdentity][l4Rule] = l7Rule
				}
			}

			for _, l4Filter := range c.L4Policy.Egress {
				found := false
				l4RuleCtx, l7RuleCtx := e.ParseL4Filter(&l4Filter)
				for _, l4RuleContexts := range egressRulesAdd {
					if _, found = l4RuleContexts[l4RuleCtx]; found {
						break
					}
				}
				if !found {
					if _, ok := egressRulesAdd[identityPkg.InvalidIdentity]; !ok {
						egressRulesAdd[identityPkg.InvalidIdentity] = policy.NewL4L7Map()
					}
					l7RuleCtx.L4Installed = true
					egressRulesAdd[identityPkg.InvalidIdentity][l4RuleCtx] = l7RuleCtx
				}
			}
		}

		// Only remove the CT entries of the rules that were successfully
		// removed (added to l4Rm) and not successfully re-added (added to rulesAdd)
		for secID, ruleCtxsRm := range ingressL4ToRemove {
			if addL4RuleCtxs, ok := ingressRulesAdd[secID]; ok {
				for addl4RuleCtx, addl7RuleCtx := range addL4RuleCtxs {
					rm, ok := ruleCtxsRm[addl4RuleCtx]
					if rm.L4Installed && ok && !(addl7RuleCtx.L4Installed) {
						if _, ok := ingressRulesRm[secID]; !ok {
							ingressRulesRm[secID] = policy.NewL4L7Map()
						}
						ingressRulesRm[secID][addl4RuleCtx] = addl7RuleCtx
					}
				}
			} else {
				// If the L3 rule was not re-added then we clean up all CT
				// entries only based on L3.
				if _, ok := ingressRulesRm[secID]; !ok {
					ingressRulesRm[secID] = policy.NewL4L7Map()
				}
				for rmL4RuleCtx, rmL7RuleCtx := range ruleCtxsRm {
					removed, ok := ingressRulesRm[secID][rmL4RuleCtx]
					rmL7RuleCtx.L4Installed = rmL7RuleCtx.L4Installed || (removed.L4Installed && ok)
					ingressRulesRm[secID][rmL4RuleCtx] = rmL7RuleCtx
				}
			}
		}

		for secID, ruleCtxsRm := range egressL4ToRemove {
			if addL4RuleCtxs, ok := egressRulesAdd[secID]; ok {
				for addl4RuleCtx, addl7RuleCtx := range addL4RuleCtxs {
					rm, ok := ruleCtxsRm[addl4RuleCtx]
					if rm.L4Installed && ok && !(addl7RuleCtx.L4Installed) {
						if _, ok := egressRulesRm[secID]; !ok {
							egressRulesRm[secID] = policy.NewL4L7Map()
						}
						egressRulesRm[secID][addl4RuleCtx] = addl7RuleCtx
					}
				}
			} else {
				// If the L3 rule was not re-added then we clean up all CT
				// entries only based on L3.
				if _, ok := egressRulesRm[secID]; !ok {
					egressRulesRm[secID] = policy.NewL4L7Map()
				}
				for rmL4RuleCtx, rmL7RuleCtx := range ruleCtxsRm {
					removed, ok := egressRulesRm[secID][rmL4RuleCtx]
					rmL7RuleCtx.L4Installed = rmL7RuleCtx.L4Installed || (removed.L4Installed && ok)
					egressRulesRm[secID][rmL4RuleCtx] = rmL7RuleCtx
				}
			}
		}
	}

	if owner.AlwaysAllowLocalhost() || c.L4Policy.HasRedirect() {
		if e.allowIngressIdentity(identityPkg.ReservedIdentityHost) {
			changed = true
		}
	}

	ingressCtx := policy.SearchContext{
		To: c.LabelArray,
	}
	egressCtx := policy.SearchContext{
		From: c.LabelArray,
	}

	if owner.TracingEnabled() {
		ingressCtx.Trace = policy.TRACE_ENABLED
		egressCtx.Trace = policy.TRACE_ENABLED
	}

	// Only L3 (label-based) policy apply.
	// Complexity increases linearly by the number of identities in the map.
	for identity, labels := range *labelsMap {
		ingressCtx.From = labels
		egressCtx.To = labels

		e.getLogger().WithFields(logrus.Fields{
			logfields.PolicyID: identity,
			"ingress_context":  ingressCtx,
		}).Debug("Evaluating ingress context for source PolicyID")

		ingressAccess := repo.AllowsIngressLabelAccess(&ingressCtx)
		if ingressAccess == api.Allowed {
			if e.allowIngressIdentity(identity) {
				changed = true
			}
		}

		e.getLogger().WithFields(logrus.Fields{
			logfields.PolicyID: identity,
			"egress_context":   egressCtx,
		}).Debug("Evaluating egress context for source PolicyID")

		egressAccess := repo.AllowsEgressLabelAccess(&egressCtx)

		log.WithFields(logrus.Fields{
			logfields.PolicyID:   identity,
			logfields.EndpointID: e.ID,
			"labels":             labels,
		}).Debugf("egress verdict: %v", egressAccess)

		if egressAccess == api.Allowed {
			e.getLogger().WithFields(logrus.Fields{
				logfields.PolicyID: identity,
				"ctx":              ingressCtx}).Debug("egress allowed")
			if e.allowEgressIdentity(identity) {
				changed = true
			}
		}
	}

	// Garbage collect all unused entries for both ingress and egress.
	for ingressIdentity, keepIdentity := range c.IngressIdentities {
		if !keepIdentity {
			c.RemoveIngressIdentityLocked(ingressIdentity)
			changed = true
			// Since we have removed an allowed security identity for ingress, the
			// L3 rule should be also be marked as removed, but only if it was
			// not previously created by a L3-L4 rule.
			if _, ok := ingressRulesRm[ingressIdentity]; !ok {
				ingressRulesRm[ingressIdentity] = policy.NewL4L7Map()
			}
			// If the L3 rule was removed then we also need to remove it from
			// the rulesAdded.
			if _, ok := ingressRulesAdd[ingressIdentity]; ok {
				delete(ingressRulesAdd, ingressIdentity)
			}
		} else {
			// Since we have (re)added a security identity upon ingress, the L3 rule
			// should be also be marked as added. But only if it was not previously
			// created by an L3-L4 rule.
			if _, ok := ingressRulesAdd[ingressIdentity]; !ok {
				ingressRulesAdd[ingressIdentity] = policy.NewL4L7Map()
			}
		}
	}

	for egressIdentity, keepIdentity := range c.EgressIdentities {
		if !keepIdentity {
			c.RemoveEgressIdentityLocked(egressIdentity)
			changed = true
			// Since we have removed an allowed security identity for ingress, the
			// L3 rule should be also be marked as removed, but only if it was
			// not previously created by a L3-L4 rule.
			if _, ok := egressRulesRm[egressIdentity]; !ok {
				egressRulesRm[egressIdentity] = policy.NewL4L7Map()
			}
			// If the L3 rule was removed then we also need to remove it from
			// the rulesAdded.
			if _, ok := ingressRulesAdd[egressIdentity]; ok {
				delete(ingressRulesAdd, egressIdentity)
			}
		} else {
			// Since we have (re)added a security identity upon ingress, the L3 rule
			// should be also be marked as added. But only if it was not previously
			// created by an L3-L4 rule.
			if _, ok := egressRulesAdd[egressIdentity]; !ok {
				egressRulesAdd[egressIdentity] = policy.NewL4L7Map()
			}
		}
	}

	if ingressRulesAdd != nil {
		ingressRulesAddCpy := ingressRulesAdd.DeepCopy() // Store the L3-L4 policy
		c.L3L4Policy = &ingressRulesAddCpy
	}

	if egressRulesAdd != nil {
		_ = egressRulesAdd.DeepCopy()
		//c.L3L4Policy = &egressRulesAddCpy
	}

	e.getLogger().WithFields(logrus.Fields{
		logfields.Identity:          c.ID,
		"ingressSecurityIdentities": logfields.Repr(c.IngressIdentities),
		"egressSecurityIdentities":  logfields.Repr(c.EgressIdentities),
		"added-ingress-rules":       ingressRulesAdd,
		"ingress-l4-rules-removed":  ingressL4ToRemove,
		"rules-removed":             ingressRulesRm,
		"added-egress-rules":        egressRulesAdd,
		"egress-l4-rules-removed":   egressL4ToRemove,
		"egress-rules-removed":      egressRulesRm,
	}).Debug("consumable regenerated")
	return changed, ingressRulesAdd, ingressRulesRm, nil
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

func (e *Endpoint) updateNetworkPolicy(owner Owner) error {
	c := e.Consumable

	deniedIngressIdentities := computeDeniedIngressIdentities(e, c, owner.GetPolicyRepository(), e.LabelsMap, owner.TracingEnabled())
	deniedEgressIdentities := computeDeniedEgressIdentities(e, c, owner.GetPolicyRepository(), e.LabelsMap, owner.TracingEnabled())

	// Publish the updated policy to L7 proxies.
	err := owner.UpdateNetworkPolicy(e, c.L4Policy, *e.LabelsMap, deniedIngressIdentities, deniedEgressIdentities)
	if err != nil {
		return err
	}

	return nil
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
// programs to avoid needing to regenerate BPF programs again right
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
//  - l4PolicyMapAdded: map of SecurityIdentityL4L7Map that contains a map of rule
// 					  contexts that were added to the L4 policy map;
//  - l4PolicyMapRemoved: map of SecurityIdentityL4L7Map that contains a map of rule
// 					    contexts that were removed from the L4 policy map;
//  - err: error in case of an error.
// Must be called with endpoint mutex held.
func (e *Endpoint) regeneratePolicy(owner Owner, opts models.ConfigurationMap) (needToRegenerateBPF bool, l4PolicyMapAdded policy.SecurityIdentityL4L7Map, l4PolicyMapRemoved policy.SecurityIdentityL4L7Map, err error) {
	// Dry mode does not regenerate policy via bpf regeneration, so we let it pass
	// through. Some bpf/redirect updates are skipped in that case.
	//
	// This can be cleaned up once we shift all bpf updates to regenerateBPF().
	if e.PolicyMap == nil && !owner.DryModeEnabled() {
		// First run always results in bpf generation
		// L4 policy generation assumes e.PolicyMap to exist, but it is only created
		// when bpf is generated for the first time. Until then we can't really compute
		// the policy. Bpf generation calls us again after PolicyMap is created.
		// In dry mode we are called with a nil PolicyMap.

		// We still need to apply any options if given.
		if opts != nil {
			e.applyOptsLocked(opts)
		}

		return false, nil, nil, nil
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
	// Use the old labelsMap instance if the new one is still the same.
	// Later we can compare the pointers to figure out if labels have changed or not.
	if reflect.DeepEqual(e.LabelsMap, labelsMap) {
		labelsMap = e.LabelsMap
	}

	repo := owner.GetPolicyRepository()
	repo.Mutex.RLock()
	revision := repo.GetRevision()
	defer repo.Mutex.RUnlock()

	// Recompute policy for this endpoint only if not already done for this revision.
	// Must recompute if labels have changed or option changes are requested.
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

	// Containers without a security identity are not accessible
	if c.ID == 0 {
		e.getLogger().Warn("Endpoint lacks identity, skipping policy calculation")
		return false, nil, nil, nil
	}

	// Skip L4 policy recomputation for this consumable if already valid.
	// Rest of the policy computation still needs to be done for each endpoint
	// separately even though the consumable may be shared between them.
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

	// Calculate L3 (CIDR) policy.
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
		e.checkEgressAccess(owner, (*labelsMap)[identityPkg.ReservedIdentityHost], opts, OptionAllowToHost)
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

	// Determines all security-identity based policy.
	// Updates e.LabelsMap to labelsMap if changed
	policyChanged2, l4PolicyMapAdded, l4PolicyMapRemoved, err := e.regenerateConsumable(owner, labelsMap, repo, c)
	if policyChanged2 {
		policyChanged = true
	}

	if err != nil {
		return false, nil, nil, err
	}
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
		e.setPolicyRevision(revision)
	}

	e.getLogger().WithFields(logrus.Fields{
		"policyChanged":       policyChanged,
		"optsChanged":         optsChanged,
		"policyRevision.next": e.nextPolicyRevision,
	}).Debug("Done regenerating")

	needToRegenerateBPF = optsChanged || policyChanged || e.nextPolicyRevision > e.policyRevision

	return needToRegenerateBPF, l4PolicyMapAdded, l4PolicyMapRemoved, nil
}

// computeDeniedIngressIdentities computes the set of identities explicitly denied
// by ingress policy.
func computeDeniedIngressIdentities(e *Endpoint, consumable *policy.Consumable, repo *policy.Repository, labelsMap *identityPkg.IdentityCache, tracingEnabled bool) map[identityPkg.NumericIdentity]bool {
	ctx := policy.SearchContext{
		To: consumable.LabelArray,
	}
	if tracingEnabled {
		ctx.Trace = policy.TRACE_ENABLED
	}
	deniedIngressIdentities := make(map[identityPkg.NumericIdentity]bool)
	for srcID, srcLabels := range *labelsMap {
		if consumable.IngressIdentities[srcID] {
			// Already allowed for L3-only.
		} else {
			ctx.From = srcLabels
			e.getLogger().WithFields(logrus.Fields{
				logfields.PolicyID: srcID,
				"ctx":              ctx,
			}).Debug("Evaluating context for source PolicyID")
			if repo.CanReachIngressRLocked(&ctx) == api.Denied {
				// Denied explicitly by fromRequires clause.
				deniedIngressIdentities[srcID] = true
			}
		}
	}

	return deniedIngressIdentities
}

// computeDeniedEgressIdentities computes the set of identities explicitly denied
// by egress policy.
func computeDeniedEgressIdentities(e *Endpoint, consumable *policy.Consumable, repo *policy.Repository, labelsMap *identityPkg.IdentityCache, tracingEnabled bool) map[identityPkg.NumericIdentity]bool {
	ctx := policy.SearchContext{
		From: consumable.LabelArray,
	}
	if tracingEnabled {
		ctx.Trace = policy.TRACE_ENABLED
	}
	deniedEgressIdentities := make(map[identityPkg.NumericIdentity]bool)
	for srcID, srcLabels := range *labelsMap {
		if consumable.EgressIdentities[srcID] {
			// Already allowed for L3-only.
		} else {
			ctx.To = srcLabels
			e.getLogger().WithFields(logrus.Fields{
				logfields.PolicyID: srcID,
				"ctx":              ctx,
			}).Debug("Evaluating context for destination PolicyID")
			if repo.CanReachEgressRLocked(&ctx) == api.Denied {
				// Denied explicitly by fromRequires clause.
				deniedEgressIdentities[srcID] = true
			}
		}
	}

	return deniedEgressIdentities
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

	// If generation fails, keep the directory around. If it ever succeeds
	// again, clean up this copy.
	failDir := tmpDir + "_fail"
	os.RemoveAll(failDir) // Most likely will not exist; ignore failure.
	if err != nil {
		e.getLogger().WithFields(logrus.Fields{
			logfields.Path: failDir,
		}).Warn("Generating BPF for endpoint failed, keeping stale directory.")
		os.Rename(tmpDir, failDir)
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
		ctCleaned = updateCT(owner, e, e.IPs(), policyEnforced, isLocal, consumersAdd, consumersRm)
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
				if e.SecurityIdentity != nil {
					id = e.SecurityIdentity.ID.String()
				}
				e.Mutex.RUnlock()

				if id != "" && e.GetK8sNamespace() != "" && e.GetK8sPodName() != "" {
					return k8s.AnnotatePod(e, common.CiliumIdentityAnnotation, id)
				}

				return nil
			},
			RunInterval: 1 * time.Minute,
		},
	)
}

// FormatGlobalEndpointID returns the global ID of endpoint in the format
// / <global ID Prefix>:<cluster name>:<node name>:<endpoint ID> as a string.
func (e *Endpoint) FormatGlobalEndpointID() string {
	nodeIdentity, _ := node.GetLocalNode()
	metadata := []string{CiliumGlobalIdPrefix, ipcache.AddressSpace, nodeIdentity.Name, strconv.Itoa(int(e.ID))}
	return strings.Join(metadata, ":")
}

// This synchronizes the key-value store with a mapping of the endpoint's IP
// with the numerical ID representing its security identity.
func (e *Endpoint) runIPIdentitySync(endpointIP addressing.CiliumIP) {

	if endpointIP == nil {
		return
	}

	addressFamily := endpointIP.GetFamilyString()
	ipKey := path.Join(ipcache.IPIdentitiesPath, ipcache.AddressSpace, endpointIP.String())

	e.controllers.UpdateController(fmt.Sprintf("sync-%s-identity-mapping (%d)", addressFamily, e.ID),
		controller.ControllerParams{
			DoFunc: func() error {

				e.Mutex.RLock()

				if e.state == StateDisconnected || e.state == StateDisconnecting {
					log.WithFields(logrus.Fields{logfields.EndpointState: e.state}).
						Debugf("not synchronizing endpoint IP with kvstore due to endpoint state")
					e.Mutex.RUnlock()
					return nil
				}

				if e.SecurityIdentity == nil {
					e.Mutex.RUnlock()
					return nil
				}
				//identityValue := e.SecurityIdentity.ID.StringID()
				ipIDPair := identityPkg.IPIdentityPair{
					IP:       endpointIP.IP(),
					ID:       e.SecurityIdentity.ID,
					Metadata: e.FormatGlobalEndpointID(),
				}

				// Release lock as we do not want to have long-lasting key-value
				// store operations resulting in lock being held for a long time.
				e.Mutex.RUnlock()

				marshaledIPIDPair, err := json.Marshal(ipIDPair)
				if err != nil {
					return err
				}

				if err := kvstore.Update(ipKey, marshaledIPIDPair, true); err != nil {
					return fmt.Errorf("unable to add endpoint IP '%s' to identity '%s': %s", ipKey, marshaledIPIDPair, err)
				}
				return nil
			},
			StopFunc: func() error {
				if err := kvstore.Delete(ipKey); err != nil {
					return fmt.Errorf("unable to delete endpoint IP '%s': %s", ipKey, err)
				}
				return nil
			},
			RunInterval: 5 * time.Minute,
		},
	)
}

// SetIdentity resets endpoint's policy identity to 'id'.
// Caller triggers policy regeneration if needed.
// Called with e.Mutex Locked
func (e *Endpoint) SetIdentity(identity *identityPkg.Identity) {
	cache := policy.GetConsumableCache()

	if e.Consumable != nil {
		if e.SecurityIdentity != nil && identity.ID == e.Consumable.ID {
			// Even if the numeric identity is the same, the order in which the
			// labels are represented may change.
			e.SecurityIdentity = identity
			e.Consumable.Mutex.Lock()
			e.Consumable.Labels = identity
			e.Consumable.LabelArray = identity.Labels.ToSlice()
			e.Consumable.Mutex.Unlock()
			return
		}
		// TODO: This removes the consumable from the cache even if other endpoints
		// would still point to it. Consumable should be removed from the cache
		// only when no endpoint refers to it. Fix by implementing explicit reference
		// counting via the cache?
		cache.Remove(e.Consumable)
	}

	e.SecurityIdentity = identity
	e.Consumable = cache.GetOrCreate(identity.ID, identity)

	// Sets endpoint state to ready if was waiting for identity
	if e.GetStateLocked() == StateWaitingForIdentity {
		e.SetStateLocked(StateReady, "Set identity for this endpoint")
	}

	e.runIdentityToK8sPodSync()

	// Whenever the identity is updated, propagate change to key-value store
	// of IP to identity mapping.
	e.runIPIdentitySync(e.IPv4)
	e.runIPIdentitySync(e.IPv6)

	e.Consumable.Mutex.RLock()
	e.getLogger().WithFields(logrus.Fields{
		logfields.Identity: identity,
		"consumable":       e.Consumable,
	}).Debug("Set identity and consumable of EP")
	e.Consumable.Mutex.RUnlock()
}
