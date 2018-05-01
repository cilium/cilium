// Copyright 2016-2018 Authors of Cilium
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
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/controller"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
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

// allowIngressIdentity must be called with global endpoint.Mutex held
func (e *Endpoint) allowIngressIdentity(id identityPkg.NumericIdentity) bool {
	return e.Consumable.AllowIngressIdentityLocked(id)
}

// allowEgressIdentity allows security identity id to be communicated to by
// this endpoint by updating the endpoint's Consumable.
// Must be called with global endpoint.Mutex held.
func (e *Endpoint) allowEgressIdentity(id identityPkg.NumericIdentity) bool {
	return e.Consumable.AllowEgressIdentityLocked(id)
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

func (e *Endpoint) sweepFilters(oldPolicy *policy.L4Policy,
	identities *identityPkg.IdentityCache) (errors int) {

	oldEntries, err := e.PolicyMap.DumpToSlice()
	if err != nil {
		e.getLogger().WithError(err).WithFields(logrus.Fields{
			logfields.PolicyRevision: oldPolicy.Revision,
		}).Warning("Delete stale l4 policy failed")
		errors++
		return
	}
	for _, entry := range oldEntries {
		id := identityPkg.NumericIdentity(entry.Key.GetIdentity())
		if _, ok := (*identities)[id]; !ok {
			if err := e.PolicyMap.DeleteEntry(&entry); err != nil {
				e.getLogger().WithError(err).WithFields(logrus.Fields{
					logfields.PolicyRevision: oldPolicy.Revision,
					logfields.Identity:       id,
				}).Warning("Delete stale l4 policy failed")
				errors++
			}
		}
	}

	return
}

// removeOldFilter removes the old l4 filter from the endpoint.
// Returns a map that represents all policies that were attempted to be removed;
// it maps to whether they were removed successfully (true or false)
func (e *Endpoint) removeOldFilter(identities *identityPkg.IdentityCache,
	filter *policy.L4Filter, direction policymap.TrafficDirection) {

	port := uint16(filter.Port)

	for _, sel := range filter.Endpoints {
		for _, id := range getSecurityIdentities(identities, &sel) {
			srcID := id.Uint32()
			if err := e.PolicyMap.Delete(srcID, port, filter.U8Proto, direction); err != nil {
				// This happens when the policy would add
				// multiple copies of the same L4 policy. Only
				// one of them is actually added, but we'll
				// still try to remove it multiple times.
				e.getLogger().WithError(err).WithFields(logrus.Fields{
					logfields.L4PolicyID:       srcID,
					logfields.TrafficDirection: direction,
				}).Debug("deletion of old L4 policy failed")

			}
		}
	}
}

// applyNewFilter adds the given l4 filter to the endpoint.
// Returns the number of errors that occurred while when applying the
// policy.
// Applies for L3-dependent L4, and not for L4-only policy.
func (e *Endpoint) applyNewFilter(identities *identityPkg.IdentityCache,
	filter *policy.L4Filter, direction policymap.TrafficDirection) int {

	port := uint16(filter.Port)
	proto := uint8(filter.U8Proto)

	errors := 0
	for _, sel := range filter.Endpoints {
		for _, id := range getSecurityIdentities(identities, &sel) {
			srcID := id.Uint32()
			if e.PolicyMap.Exists(srcID, port, filter.U8Proto, direction) {
				e.getLogger().WithField("l4Filter", filter).Debug("L4 filter exists")
				continue
			}
			if err := e.PolicyMap.Allow(srcID, port, filter.U8Proto, direction); err != nil {
				e.getLogger().WithFields(logrus.Fields{
					logfields.PolicyID: srcID,
					logfields.Port:     port,
					logfields.Protocol: proto}).WithError(err).Warn(
					"Update of l4 policy map failed")
				errors++
			}
		}
	}
	return errors
}

// Looks for mismatches between 'oldPolicy' and 'newPolicy', and fixes up
// this Endpoint's BPF PolicyMap to reflect the new L3+L4 combined policy.
// Returns a map that represents all L3-dependent L4 PolicyMap entries that were attempted
// to be added;
// and a map that represents all L3-dependent L4 PolicyMap entries that were attempted
// to be removed;
// it maps to whether they were removed successfully (true or false)
// TODO (it maps to rule contexts); 'whether they were removed successfully' doesn't
// make sense - is this what L4Installed means?
func (e *Endpoint) applyL4PolicyLocked(oldIdentities, newIdentities *identityPkg.IdentityCache,
	oldL4Policy, newL4Policy *policy.L4Policy) (err error) {

	var errors = 0

	// Need to iterate through old L3-L4 policy and remove all PolicyMap entries
	// for both ingress and egress.
	if oldL4Policy != nil {
		for _, filter := range oldL4Policy.Ingress {
			e.removeOldFilter(oldIdentities, &filter, policymap.Ingress)
		}

		for _, filter := range oldL4Policy.Egress {
			e.removeOldFilter(oldIdentities, &filter, policymap.Egress)
		}
		errors += e.sweepFilters(oldL4Policy, newIdentities)
	}

	// No new entries to add to PolicyMap, so simply return.
	if newL4Policy == nil {
		return nil
	}

	// Need to iterate through new L3-L4 policy and insert new PolicyMap entries
	// for both ingress and egress.
	for _, filter := range newL4Policy.Ingress {
		var errs int
		errs = e.applyNewFilter(newIdentities, &filter, policymap.Ingress)
		errors += errs
	}

	for _, filter := range newL4Policy.Egress {
		errs := e.applyNewFilter(newIdentities, &filter, policymap.Egress)
		errors += errs
	}

	if errors > 0 {
		return fmt.Errorf("Some Label+L4 policy updates failed.")
	}
	return nil
}

func getLabelsMap() (*identityPkg.IdentityCache, error) {
	labelsMap := identityPkg.GetIdentityCache()

	reservedIDs := identityPkg.GetAllReservedIdentities()
	var idx identityPkg.NumericIdentity
	for _, idx = range reservedIDs {
		identity := identityPkg.LookupIdentityByID(idx)
		if identity == nil {
			return nil, fmt.Errorf("unable to resolve reserved identity")
		}
		lbls := identity.Labels.ToSlice()
		if len(lbls) == 0 {
			return nil, fmt.Errorf("unable to resolve reserved identity")
		}
		labelsMap[idx] = lbls
	}

	return &labelsMap, nil
}

// Must be called with global endpoint.Mutex held
func (e *Endpoint) resolveL4Policy(owner Owner, repo *policy.Repository, c *policy.Consumable) error {

	ingressCtx := policy.SearchContext{
		To: e.SecurityIdentity.LabelArray,
	}

	egressCtx := policy.SearchContext{
		From: e.SecurityIdentity.LabelArray,
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
	repo *policy.Repository, c *policy.Consumable) (changed bool, err error) {

	// Mark all entries unused by denying them
	for ingressIdentity := range c.IngressIdentities {
		// Mark as false indicates denying
		c.IngressIdentities[ingressIdentity] = false
	}

	for egressIdentity := range c.EgressIdentities {
		c.EgressIdentities[egressIdentity] = false
	}

	// L4 policy needs to be applied on two conditions
	// 1. The L4 policy has changed
	// 2. The set of applicable security identities has changed.
	if e.L4Policy != c.L4Policy || e.LabelsMap != labelsMap {
		e.getLogger().Debug("policy changed to L4Policy or LabelsMap having changed")
		changed = true

		// PolicyMap can't be created in dry mode.
		if !owner.DryModeEnabled() {
			// Collect unused redirects.
			err = e.applyL4PolicyLocked(e.LabelsMap, labelsMap, e.L4Policy, c.L4Policy)
			if err != nil {
				// This should not happen, and we can't fail at this stage anyway.
				e.getLogger().WithError(err).Error("L4 Policy application failed")
				return
			}
		}
		// Reuse the common policy, will be used in lxc_config.h (CFG_CIDRL4_INGRESS and CFG_CIDRL4_EGRESS)
		e.L4Policy = c.L4Policy
		e.LabelsMap = labelsMap // Remember the set of labels used
	}

	if owner.AlwaysAllowLocalhost() || c.L4Policy.HasRedirect() {
		if e.allowIngressIdentity(identityPkg.ReservedIdentityHost) {
			e.getLogger().WithFields(logrus.Fields{
				logfields.PolicyID: identityPkg.ReservedIdentityHost,
			}).Debug("policy changed due to allowing host identity when it previously was not allowed")
			changed = true
		}
	}

	ingressCtx := policy.SearchContext{
		To: e.SecurityIdentity.LabelArray,
	}
	egressCtx := policy.SearchContext{
		From: e.SecurityIdentity.LabelArray,
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
				e.getLogger().WithFields(logrus.Fields{
					logfields.PolicyID: identity,
				}).Debug("policy changed due to allowing previously disallowed identity on ingress")
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
				e.getLogger().WithFields(logrus.Fields{
					logfields.PolicyID: identity,
				}).Debug("policy changed due to allowing previously disallowed identity on egress")
				changed = true
			}
		}
	}

	// Garbage collect all unused entries for both ingress and egress.
	for ingressIdentity, keepIdentity := range c.IngressIdentities {
		if !keepIdentity {

			e.getLogger().WithFields(logrus.Fields{
				logfields.PolicyID: ingressIdentity,
			}).Debug("policy changed due to disallowing previously allowed identity on ingress")

			c.RemoveIngressIdentityLocked(ingressIdentity)
			changed = true
		}
	}

	for egressIdentity, keepIdentity := range c.EgressIdentities {
		if !keepIdentity {
			e.getLogger().WithFields(logrus.Fields{
				logfields.PolicyID: egressIdentity,
			}).Debug("policy changed due to disallowing previously allowed identity on egress")
			c.RemoveEgressIdentityLocked(egressIdentity)
			changed = true
		}
	}

	e.getLogger().WithFields(logrus.Fields{
		logfields.Identity:          c.ID,
		"ingressSecurityIdentities": logfields.Repr(c.IngressIdentities),
		"egressSecurityIdentities":  logfields.Repr(c.EgressIdentities),
	}).Debug("consumable regenerated")
	return changed, nil
}

// Must be called with global repo.Mutrex, e.Mutex, and c.Mutex held
func (e *Endpoint) regenerateL3Policy(owner Owner, repo *policy.Repository, revision uint64, c *policy.Consumable) (bool, error) {

	ctx := policy.SearchContext{
		To: e.SecurityIdentity.LabelArray, // keep c.Mutex taken to protect this.
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
	// Skip updating the NetworkPolicy if no policy has been calculated.
	// This breaks a circular dependency between configuring NetworkPolicies in
	// sidecar Envoy proxies and those proxies needing network connectivity
	// to get their initial configuration, which is required for them to ACK
	// the NetworkPolicies.
	if !e.PolicyCalculated {
		return nil
	}

	// Compute the set of identities explicitly denied by policy.
	// This loop is similar to the one in regenerateConsumable called
	// above, but this set only contains the identities with "Denied" verdicts.
	c := e.Consumable
	ctx := policy.SearchContext{
		To: e.SecurityIdentity.LabelArray,
	}
	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}
	deniedIngressIdentities := make(map[identityPkg.NumericIdentity]bool)
	for srcID, srcLabels := range *e.LabelsMap {
		if c.IngressIdentities[srcID] {
			// Already allowed for L3-only.
		} else {
			ctx.From = srcLabels
			e.getLogger().WithFields(logrus.Fields{
				logfields.PolicyID: srcID,
				"ctx":              ctx,
			}).Debug("Evaluating context for source PolicyID")
			repo := owner.GetPolicyRepository()
			if repo.CanReachIngressRLocked(&ctx) == api.Denied {
				// Denied explicitly by fromRequires clause.
				deniedIngressIdentities[srcID] = true
			}
		}
	}

	// Reset SearchContext to reflect change in directionality.
	ctx = policy.SearchContext{
		From: e.SecurityIdentity.LabelArray,
	}

	deniedEgressIdentities := make(map[identityPkg.NumericIdentity]bool)
	for dstID, dstLabels := range *e.LabelsMap {
		if c.EgressIdentities[dstID] {
			// Already allowed for L3-only.
		} else {
			ctx.To = dstLabels
			e.getLogger().WithFields(logrus.Fields{
				logfields.PolicyID: dstID,
				"ctx":              ctx,
			}).Debug("Evaluating context for destination PolicyID")
			repo := owner.GetPolicyRepository()
			if repo.CanReachEgressRLocked(&ctx) == api.Denied {
				// Denied explicitly by toRequires clause.
				deniedEgressIdentities[dstID] = true
			}
		}
	}

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
//  - err: error in case of an error.
// Must be called with endpoint mutex held.
func (e *Endpoint) regeneratePolicy(owner Owner, opts models.ConfigurationMap) (bool, error) {
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
		e.getLogger().Debug("marking policy as changed to trigger bpf generation as part of first build")
		return true, nil
	}

	e.getLogger().Debug("Starting regenerate...")

	// Collect label arrays before policy computation, as this can fail.
	// GH-1128 should allow optimizing this away, but currently we can't
	// reliably know if the KV-store has changed or not, so we must scan
	// through it each time.
	labelsMap, err := getLabelsMap()
	if err != nil {
		e.getLogger().WithError(err).Debug("Received error while evaluating policy")
		return false, err
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
			"policyChanged":       e.nextPolicyRevision > e.policyRevision,
		}).Debug("skipping policy recalculation")
		// This revision already computed, but may still need to be applied to BPF
		return e.nextPolicyRevision > e.policyRevision, nil
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
		return false, nil
	}

	// Skip L4 policy recomputation for this consumable if already valid.
	// Rest of the policy computation still needs to be done for each endpoint
	// separately even though the consumable may be shared between them.
	if c.Iteration != revision {
		err = e.resolveL4Policy(owner, repo, c)
		if err != nil {
			return false, err
		}
		// Result is valid until cache iteration advances
		c.Iteration = revision
	} else {
		e.getLogger().WithField(logfields.Identity, c.ID).Debug("Reusing cached L4 policy")
	}

	// Calculate L3 (CIDR) policy.
	var policyChanged bool
	if policyChanged, err = e.regenerateL3Policy(owner, repo, revision, c); err != nil {
		return false, err
	}

	if policyChanged {
		e.getLogger().Debug("regeneration of L3 (CIDR) policy caused policy change")
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

	if !ingress && !egress {
		e.getLogger().Debug("ingress and egress policy enforcement not enabled")
	} else {
		if ingress && egress {
			e.getLogger().Debug("policy enforcement for ingress and egress enabled")
			opts[OptionIngressPolicy] = optionEnabled
			opts[OptionEgressPolicy] = optionEnabled
		} else if ingress {
			e.getLogger().Debug("policy enforcement for ingress enabled")
			opts[OptionIngressPolicy] = optionEnabled
		} else {
			e.getLogger().Debug("policy enforcement for egress enabled")
			opts[OptionEgressPolicy] = optionEnabled
		}
	}

	optsChanged := e.applyOptsLocked(opts)

	// Determines all security-identity based policy.
	// Updates e.LabelsMap to labelsMap if changed
	policyChanged2, err := e.regenerateConsumable(owner, labelsMap, repo, c)
	if err != nil {
		return false, err
	}
	if policyChanged2 {
		e.getLogger().Debug("consumable regeneration resulted in policy change")
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

	needToRegenerateBPF := optsChanged || policyChanged || e.nextPolicyRevision > e.policyRevision

	return needToRegenerateBPF, nil
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
	// again, clean up the XXX_next_fail copy.
	failDir := e.failedDirectoryPath()
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
// Should only be called with e.state == StateWaitingToRegenerate or with
// e.state == StateWaitingForIdentity
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
func (e *Endpoint) TriggerPolicyUpdatesLocked(owner Owner, opts models.ConfigurationMap) (bool, error) {

	if e.Consumable == nil {
		return false, nil
	}

	needToRegenerateBPF, err := e.regeneratePolicy(owner, opts)
	if err != nil {
		return false, fmt.Errorf("%s: %s", e.StringID(), err)
	}

	e.getLogger().Debugf("TriggerPolicyUpdatesLocked: changed: %t", needToRegenerateBPF)

	return needToRegenerateBPF, nil
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

				IP := endpointIP.IP()
				ID := e.SecurityIdentity.ID
				metadata := e.FormatGlobalEndpointID()

				// Release lock as we do not want to have long-lasting key-value
				// store operations resulting in lock being held for a long time.
				e.Mutex.RUnlock()

				if err := ipcache.UpsertIPToKVStore(IP, ID, metadata); err != nil {
					return fmt.Errorf("unable to add endpoint IP mapping '%s'->'%d': %s", IP.String(), ID, err)
				}
				return nil
			},
			StopFunc: func() error {
				ip := endpointIP.String()
				if err := ipcache.DeleteIPFromKVStore(ip); err != nil {
					return fmt.Errorf("unable to delete endpoint IP '%s' from ipcache: %s", ip, err)
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

	if e.Consumable != nil {
		if e.SecurityIdentity != nil && identity.ID == e.Consumable.ID {
			// Even if the numeric identity is the same, the order in which the
			// labels are represented may change.
			e.SecurityIdentity = identity
			return
		}
	}

	oldIdentity := "no identity"
	if e.SecurityIdentity != nil {
		oldIdentity = e.SecurityIdentity.StringID()
	}

	e.SecurityIdentity = identity
	e.Consumable = policy.NewConsumable(identity.ID, identity)

	// Sets endpoint state to ready if was waiting for identity
	if e.GetStateLocked() == StateWaitingForIdentity {
		e.SetStateLocked(StateReady, "Set identity for this endpoint")
	}

	e.runIdentityToK8sPodSync()

	// Whenever the identity is updated, propagate change to key-value store
	// of IP to identity mapping.
	e.runIPIdentitySync(e.IPv4)
	e.runIPIdentitySync(e.IPv6)

	e.getLogger().WithFields(logrus.Fields{
		logfields.Identity:       identity.StringID(),
		logfields.OldIdentity:    oldIdentity,
		logfields.IdentityLabels: identity.Labels.String(),
	}).Info("Identity of endpoint changed")
}
