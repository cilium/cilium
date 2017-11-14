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
	"os"
	"path/filepath"
	"reflect"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/cilium/cilium/common"
	log "github.com/sirupsen/logrus"
)

func (e *Endpoint) checkEgressAccess(owner Owner, dstLabels labels.LabelArray, opts models.ConfigurationMap, opt string) {
	ctx := policy.SearchContext{
		From: e.Consumable.LabelArray,
		To:   dstLabels,
	}

	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}

	scopedLog := e.getLogger().WithFields(log.Fields{
		logfields.Labels + ".from": ctx.From,
		logfields.Labels + ".to":   ctx.To,
	})

	switch owner.GetPolicyRepository().AllowsLabelAccess(&ctx) {
	case api.Allowed:
		opts[opt] = "enabled"
		scopedLog.Debug("checkEgressAccess: Enabled")
	case api.Denied:
		opts[opt] = "disabled"
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

func (e *Endpoint) cleanUnusedRedirects(owner Owner, oldMap policy.L4PolicyMap, newMap policy.L4PolicyMap) {
	for k, v := range oldMap {
		if newMap != nil {
			// Keep redirects which are also in the new policy
			if _, ok := newMap[k]; ok {
				continue
			}
		}

		if v.IsRedirect() {
			if err := owner.RemoveProxyRedirect(e, &v); err != nil {
				e.getLogger().WithError(err).WithField("redirect", v).Warn("Error while removing proxy redirect")
			}

		}
	}
}

func getSecurityIdentities(labelsMap *LabelsMap, selector *api.EndpointSelector) []policy.NumericIdentity {
	identities := []policy.NumericIdentity{}
	for idx, labels := range *labelsMap {
		if selector.Matches(labels) {
			log.WithFields(log.Fields{
				logfields.IdentityLabels: labels,
				logfields.L4PolicyID:     idx,
			}).Debug("L4 Policy matches")
			identities = append(identities, idx)
		}
	}

	return identities
}

func (e *Endpoint) removeOldFilter(labelsMap *LabelsMap, filter *policy.L4Filter) {
	port := uint16(filter.Port)
	proto := uint8(filter.U8Proto)

	for _, sel := range filter.FromEndpoints {
		for _, id := range getSecurityIdentities(labelsMap, &sel) {
			srcID := id.Uint32()
			if err := e.PolicyMap.DeleteL4(srcID, port, proto); err != nil {
				// This happens when the policy would add
				// multiple copies of the same L4 policy. Only
				// one of them is actually added, but we'll
				// still try to remove it multiple times.
				e.getLogger().WithError(err).WithField(logfields.L4PolicyID, srcID).Debug("Delete old l4 policy failed")
			}
		}
	}
}

func (e *Endpoint) applyNewFilter(labelsMap *LabelsMap, filter *policy.L4Filter) int {
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
			if err := e.PolicyMap.AllowL4(srcID, port, proto); err != nil {
				e.getLogger().WithError(err).Warn("Update of l4 policy map failed")
				errors++
			}
		}
	}

	return errors
}

// Looks for mismatches between 'oldPolicy' and 'newPolicy', and fixes up
// this Endpoint's BPF PolicyMap to reflect the new L3+L4 combined policy.
func (e *Endpoint) applyL4PolicyLocked(labelsMap *LabelsMap, oldPolicy *policy.L4Policy, newPolicy *policy.L4Policy) error {
	if oldPolicy != nil {
		for _, filter := range oldPolicy.Ingress {
			e.removeOldFilter(labelsMap, &filter)
		}
	}

	if newPolicy == nil {
		return nil
	}

	errors := 0

	for _, filter := range newPolicy.Ingress {
		errors += e.applyNewFilter(labelsMap, &filter)
	}

	if errors > 0 {
		return fmt.Errorf("Some Label+L4 policy updates failed.")
	}
	return nil
}

func getLabelsMap(owner Owner) (*LabelsMap, error) {
	maxID, err := owner.GetCachedMaxLabelID()
	if err != nil {
		return nil, err
	}

	labelsMap := LabelsMap{}

	reservedIDs := policy.GetConsumableCache().GetReservedIDs()
	var idx policy.NumericIdentity
	for _, idx = range reservedIDs {
		lbls, err := owner.GetCachedLabelList(idx)
		if err != nil {
			return nil, err
		}
		// Skip currently unused IDs
		if lbls == nil || len(lbls) == 0 {
			continue
		}
		labelsMap[idx] = lbls
	}

	for idx = policy.MinimalNumericIdentity; idx < maxID; idx++ {
		lbls, err := owner.GetCachedLabelList(idx)
		if err != nil {
			return nil, err
		}
		// Skip currently unused IDs
		if lbls == nil || len(lbls) == 0 {
			continue
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
func (e *Endpoint) regenerateConsumable(owner Owner, labelsMap *LabelsMap, repo *policy.Repository, c *policy.Consumable) bool {
	changed := false

	// Mark all entries unused by denying them
	for k := range c.Consumers {
		c.Consumers[k].DeletionMark = true
	}

	// L4 policy needs to be applied on two conditions
	// 1. The L4 policy has changed
	// 2. The set of applicable security identities has changed.
	if e.L4Policy != c.L4Policy || e.LabelsMap != labelsMap {
		// PolicyMap can't be created in dry mode.
		if !owner.DryModeEnabled() {
			// Update Endpoint's L4Policy
			if e.L4Policy != nil {
				e.cleanUnusedRedirects(owner, e.L4Policy.Ingress, c.L4Policy.Ingress)
				e.cleanUnusedRedirects(owner, e.L4Policy.Egress, c.L4Policy.Egress)
			}

			err := e.applyL4PolicyLocked(labelsMap, e.L4Policy, c.L4Policy)
			if err != nil {
				// This should not happen, and we can't fail at this stage anyway.
				e.getLogger().Fatal("L4 Policy application failed")
			}
		}
		e.L4Policy = c.L4Policy // Reuse the common policy
		e.LabelsMap = labelsMap // Remember the set of labels used
		changed = true
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
		e.getLogger().WithFields(log.Fields{
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
		}
	}

	e.getLogger().WithFields(log.Fields{
		logfields.Identity: c.ID,
		"consumers":        logfields.Repr(c.Consumers),
	}).Debug("New consumable with consumers")

	return changed
}

// Must be called with global repo.Mutrex, e.Mutex, and c.Mutex held
func (e *Endpoint) regenerateL3Policy(owner Owner, repo *policy.Repository, revision uint64, c *policy.Consumable) (bool, error) {

	ctx := policy.SearchContext{
		To: c.LabelArray, // keep c.Mutex taken to protect this.
	}
	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}
	newL3policy := repo.ResolveL3Policy(&ctx)
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
// Must be called with endpoint mutex held.
func (e *Endpoint) regeneratePolicy(owner Owner, opts models.ConfigurationMap) (bool, error) {
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

		return true, nil
	}

	e.getLogger().Debug("Starting regenerate...")

	// Collect label arrays before policy computation, as this can fail.
	// GH-1128 should allow optimizing this away, but currently we can't
	// reliably know if the KV-store has changed or not, so we must scan
	// through it each time.
	labelsMap, err := getLabelsMap(owner)
	if err != nil {
		e.getLogger().WithError(err).Debug("Received error while evaluating policy")
		return false, err
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

		e.getLogger().WithFields(log.Fields{
			"policyRevision.next": e.nextPolicyRevision,
			"policyRevision.repo": revision,
		}).Debug("Skipping policy recalculation")
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

	// Containers without a security label are not accessible
	if c.ID == 0 {
		e.getLogger().Warn("Endpoint lacks identity, skipping policy calculation")
		return false, nil
	}

	// Skip L4 policy recomputation for this consumable if already valid.
	// Rest of the policy computation still needs to be done for each endpoint
	// separately even thought the consumable may be shared between them.
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

	var policyChanged bool
	if policyChanged, err = e.regenerateL3Policy(owner, repo, revision, c); err != nil {
		return false, err
	}

	// no failures after this point

	// Apply possible option changes before regenerating maps, as map regeneration
	// depends on the conntrack options
	if c.L4Policy != nil {
		if c.L4Policy.RequiresConntrack() {
			opts[OptionConntrack] = "enabled"
		}
	}

	e.checkEgressAccess(owner, (*labelsMap)[policy.ReservedIdentityHost], opts, OptionAllowToHost)
	e.checkEgressAccess(owner, (*labelsMap)[policy.ReservedIdentityWorld], opts, OptionAllowToWorld)

	if owner.EnableEndpointPolicyEnforcement(e) {
		e.getLogger().Info("Policy enabled")
		opts[OptionPolicy] = "enabled"
	} else {
		e.getLogger().Info("Policy disabled")
		opts[OptionPolicy] = "disabled"
	}

	optsChanged := e.applyOptsLocked(opts)

	if e.regenerateConsumable(owner, labelsMap, repo, c) {
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
		e.getLogger().Info("Forced rebuild")
	}

	e.nextPolicyRevision = revision

	// If no policy or options change occurred for this endpoint then the endpoint is
	// already running the latest revision, otherwise we have to wait for
	// the regeneration of the endpoint to complete.
	if !policyChanged && !optsChanged {
		e.policyRevision = revision
		e.updateLogger()
	}

	e.getLogger().WithFields(log.Fields{
		"policyChanged":       policyChanged,
		"optsChanged":         optsChanged,
		"policyRevision.next": e.nextPolicyRevision,
	}).Debug("Done regenerating")

	// Return true if need to regenerate BPF
	return optsChanged || policyChanged || e.nextPolicyRevision > e.policyRevision, nil
}

// Called with e.Mutex UNlocked
func (e *Endpoint) regenerate(owner Owner, reason string) error {
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

	if err := e.regenerateBPF(owner, tmpDir, reason); err != nil {
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
			e.getLogger().WithFields(log.Fields{
				logfields.Path: backupDir,
			}).Warn("Restoring directory for endpoint failed, endpoint " +
				"is in inconsistent state. Keeping stale directory.")
			return err2
		}

		return fmt.Errorf("Restored original endpoint directory, atomic replace failed: %s", err)
	}

	os.RemoveAll(backupDir)

	// Set to Ready, but only if no other changes are pending.
	// State will remain as waiting-to-regenerate if further
	// changes are needed. There should be an another regenerate
	// queued for taking care of it.
	e.Mutex.Lock()
	e.BuilderSetStateLocked(StateReady, "Completed endpoint regeneration with no pending regeneration requests")
	e.getLogger().Info("Regenerated program of endpoint")
	e.Mutex.Unlock()

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
				e.LogStatus(BPF, Failure, "Error regenerating endpoint: "+err.Error())
			} else {
				buildSuccess = true
				e.LogStatusOK(BPF, "Successfully regenerated endpoint program due to "+reason)
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

	changed, err := e.regeneratePolicy(owner, opts)
	if err != nil {
		return false, fmt.Errorf("%s: %s", e.StringID(), err)
	}

	e.getLogger().Debugf("TriggerPolicyUpdatesLocked: changed: %d", changed)

	return changed, nil
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
	e.LabelsHash = e.SecLabel.Labels.SHA256Sum()
	e.Consumable = cache.GetOrCreate(id.ID, id)

	// Sets endpoint state to ready if was waiting for identity
	if e.GetStateLocked() == StateWaitingForIdentity {
		e.SetStateLocked(StateReady, "Set identity for this endpoint")
	}

	// Annotate pod that this endpoint represents with its security identity
	go owner.AnnotateEndpoint(e, common.CiliumIdentityAnnotation, e.SecLabel.ID.String())
	e.Consumable.Mutex.RLock()
	e.getLogger().WithFields(log.Fields{
		logfields.Identity: id,
		"consumable":       e.Consumable,
	}).Debug("Set identity and consumable of EP")
	e.Consumable.Mutex.RUnlock()
}
