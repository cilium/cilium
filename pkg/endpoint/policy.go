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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/cilium/cilium/common"
	log "github.com/sirupsen/logrus"
)

func (e *Endpoint) checkEgressAccess(owner Owner, opts models.ConfigurationMap, dstID policy.NumericIdentity, opt string) {
	var err error

	ctx := policy.SearchContext{
		From: e.Consumable.LabelArray,
	}

	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}

	ctx.To, err = owner.GetCachedLabelList(dstID)
	if err != nil {
		e.getLogger().WithField(logfields.PolicyID, dstID).Warn("Unable to get label list for policy, access for endpoint may be restricted")
		return
	}

	switch owner.GetPolicyRepository().AllowsLabelAccess(&ctx) {
	case api.Allowed:
		opts[opt] = "enabled"
	case api.Denied:
		opts[opt] = "disabled"
	}
}

// allowConsumer must be called with global endpoint.Mutex held
func (e *Endpoint) allowConsumer(owner Owner, id policy.NumericIdentity) {
	cache := policy.GetConsumableCache()
	if !e.Opts.IsEnabled(OptionConntrack) {
		e.Consumable.AllowConsumerAndReverseLocked(cache, id)
	} else {
		e.Consumable.AllowConsumerLocked(cache, id)
	}
}

func (e *Endpoint) evaluateConsumerSource(owner Owner, ctx *policy.SearchContext, srcID policy.NumericIdentity) error {
	var err error

	ctx.From, err = owner.GetCachedLabelList(srcID)
	if err != nil {
		return err
	}

	// Skip currently unused IDs
	if ctx.From == nil || len(ctx.From) == 0 {
		return nil
	}

	e.getLogger().WithFields(log.Fields{
		logfields.PolicyID: srcID,
		"ctx":              ctx,
	}).Debug("Evaluating context for source PolicyID")

	if owner.GetPolicyRepository().AllowsLabelAccess(ctx) == api.Allowed {
		e.allowConsumer(owner, srcID)
	}

	return nil
}

func (e *Endpoint) invalidatePolicy() {
	if e.Consumable != nil {
		e.getLogger().Debug("Invalidated policy for endpoint")

		// Resetting to 0 will trigger a regeneration on the next update
		e.Consumable.Mutex.Lock()
		e.Consumable.Iteration = 0
		e.Consumable.Mutex.Unlock()
	}
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
				e.getLogger().WithError(err).WithField("redirect", v).Warn("error while removing proxy redirect")
			}

		}
	}
}

func getSecurityIdentities(owner Owner, selector *api.EndpointSelector) []policy.NumericIdentity {
	identities := []policy.NumericIdentity{}
	maxID, err := owner.GetCachedMaxLabelID()
	if err != nil {
		return identities
	}
	for idx := policy.MinimalNumericIdentity; idx < maxID; idx++ {
		labels, err := owner.GetCachedLabelList(idx)
		if err != nil {
			log.WithError(err).WithField(logfields.IdentityLabels, labels).Info("L4 Policy label lookup failed")
		}

		if labels != nil && selector.Matches(labels) {
			log.WithFields(log.Fields{
				logfields.IdentityLabels: labels,
				logfields.L4PolicyID:     idx,
			}).Debug("L4 Policy matches.")
			identities = append(identities, idx)
		}
	}

	return identities
}

func (e *Endpoint) removeOldFilter(owner Owner, filter *policy.L4Filter) int {
	port := uint16(filter.Port)
	proto, err := u8proto.ParseProtocol(string(filter.Protocol))
	if err != nil {
		e.getLogger().WithError(err).Warn("Parse policy protocol failed")
		return 1
	}

	errors := 0
	for _, sel := range filter.FromEndpoints {
		for _, id := range getSecurityIdentities(owner, &sel) {
			srcID := id.Uint32()
			if err = e.PolicyMap.DeleteL4(srcID, port, uint8(proto)); err != nil {
				e.getLogger().WithError(err).WithField(logfields.L4PolicyID, srcID).Debug("Delete old l4 policy failed")
			}
		}
	}

	return errors
}

func (e *Endpoint) applyNewFilter(owner Owner, filter *policy.L4Filter) int {
	port := uint16(filter.Port)
	proto, err := u8proto.ParseProtocol(string(filter.Protocol))
	if err != nil {
		e.getLogger().WithError(err).Warn("Parse policy protocol failed")
		return 1
	}

	errors := 0
	for _, sel := range filter.FromEndpoints {
		for _, id := range getSecurityIdentities(owner, &sel) {
			srcID := id.Uint32()
			if e.PolicyMap.L4Exists(srcID, port, uint8(proto)) {
				e.getLogger().WithField("l4Filter", filter).Debug("L4 filter exists")
				continue
			}
			if err = e.PolicyMap.AllowL4(srcID, port, uint8(proto)); err != nil {
				e.getLogger().WithError(err).Warn("Update of l4 policy map failed")
				errors++
			}
		}
	}

	return errors
}

// Looks for mismatches between 'oldPolicy' and 'newPolicy', and fixes up
// this Endpoint's BPF PolicyMap to reflect the new L3+L4 combined policy.
func (e *Endpoint) applyL4PolicyLocked(owner Owner, oldPolicy *policy.L4Policy, newPolicy *policy.L4Policy) error {
	errors := 0

	if oldPolicy != nil {
		for _, filter := range oldPolicy.Ingress {
			errors = e.removeOldFilter(owner, &filter)
		}
	}

	if newPolicy == nil {
		return nil
	}

	for _, filter := range newPolicy.Ingress {
		errors += e.applyNewFilter(owner, &filter)
	}

	if errors > 0 {
		return fmt.Errorf("Some Label+L4 policy updates failed.")
	}
	return nil
}

// Must be called with global endpoint.Mutex held
func (e *Endpoint) regenerateConsumable(owner Owner) (bool, error) {
	c := e.Consumable

	// Endpoints without a security label are not accessible
	if c.ID == 0 {
		e.getLogger().Warn("Endpoint lacks identity, skipping policy calculation")

		return false, nil
	}

	cache := policy.GetConsumableCache()

	// Skip if policy for this consumable is already valid
	//if c.Iteration == cache.Iteration {
	//	repo.Mutex.RUnlock()
	//	e.getLogger().WithField("consumableID", c.ID).Debug("Reusing cached policy for consumable identity")
	//	return false, nil
	//}

	maxID, err := owner.GetCachedMaxLabelID()
	if err != nil {
		return false, err
	}

	c.Mutex.RLock()
	ctx := policy.SearchContext{
		To: c.LabelArray,
	}
	c.Mutex.RUnlock()

	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}

	repo := owner.GetPolicyRepository()
	repo.Mutex.Lock()
	newL4policy, err := repo.ResolveL4Policy(&ctx)
	defer repo.Mutex.Unlock()

	if err != nil {
		return false, err
	}

	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	// Mark all entries unused by denying them
	for k := range c.Consumers {
		c.Consumers[k].DeletionMark = true
	}

	if c.L4Policy != nil {
		e.cleanUnusedRedirects(owner, c.L4Policy.Ingress, newL4policy.Ingress)
		e.cleanUnusedRedirects(owner, c.L4Policy.Egress, newL4policy.Egress)
	}

	err = e.applyL4PolicyLocked(owner, c.L4Policy, newL4policy)
	if err != nil {
		return false, err
	}
	c.L4Policy = newL4policy

	if newL4policy.HasRedirect() || owner.AlwaysAllowLocalhost() {
		e.allowConsumer(owner, policy.ReservedIdentityHost)
	}

	// Check access from reserved consumables first
	reservedIDs := cache.GetReservedIDs()
	for _, id := range reservedIDs {
		if err := e.evaluateConsumerSource(owner, &ctx, id); err != nil {
			// This should never really happen
			// FIXME: clear policy because it is inconsistent
			e.getLogger().WithError(err).Debug("Received error while evaluating policy")
		}
	}

	// Iterate over all possible assigned search contexts
	idx := policy.MinimalNumericIdentity
	e.getLogger().WithField("range", []policy.NumericIdentity{idx, maxID}).Debug("Eval ID range")
	for idx < maxID {
		if err := e.evaluateConsumerSource(owner, &ctx, idx); err != nil {
			// FIXME: clear policy because it is inconsistent
			e.getLogger().WithError(err).Debug("Received error while evaluating policy")
		}
		idx++
	}

	// Garbage collect all unused entries
	for _, val := range c.Consumers {
		if val.DeletionMark {
			val.DeletionMark = false
			c.BanConsumerLocked(val.ID)
		}
	}

	// Result is valid until cache iteration advances
	c.Iteration = repo.GetRevision()

	e.getLogger().WithFields(log.Fields{
		"consumableID": c.ID,
		"consumers":    logfields.Repr(c.Consumers),
	}).Debug("new consumable with consumers")

	// FIXME: Optimize this and only return true if L4 policy changed
	return true, nil
}

// Must be called with global endpoint.Mutex held
func (e *Endpoint) regenerateL3Policy(owner Owner) (bool, error) {
	c := e.Consumable

	repo := owner.GetPolicyRepository()
	repo.Mutex.Lock() // Must be taken before c.Mutex
	c.Mutex.RLock()
	ctx := policy.SearchContext{
		To:    c.LabelArray, // keep c.Mutex taken to protect this.
		Trace: policy.TRACE_VERBOSE,
	}
	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}
	newL3policy := repo.ResolveL3Policy(&ctx)
	// Perform the validation on the new policy
	err := newL3policy.Validate()
	valid := err == nil
	repo.Mutex.Unlock()
	c.Mutex.RUnlock()

	if valid {
		e.L3Policy = newL3policy
	}

	// FIXME: Optimize this and only return true if L3 policy changed
	return valid, err
}

// regeneratePolicy returns whether the policy for the given endpoint should be
// regenerated. Only called when e.Consumable != nil.
func (e *Endpoint) regeneratePolicy(owner Owner) (bool, error) {
	e.getLogger().Debug("Starting regenerate...")

	policyChanged, err := e.regenerateConsumable(owner)
	if err != nil {
		return false, err
	}

	l3PolicyChanged, err := e.regenerateL3Policy(owner)
	if err != nil {
		return false, err
	}
	if l3PolicyChanged {
		policyChanged = true
	}

	opts := make(models.ConfigurationMap)
	repo := owner.GetPolicyRepository()
	repo.Mutex.RLock()
	revision := repo.GetRevision()
	e.Consumable.Mutex.RLock()

	e.checkEgressAccess(owner, opts, policy.ReservedIdentityHost, OptionAllowToHost)
	e.checkEgressAccess(owner, opts, policy.ReservedIdentityWorld, OptionAllowToWorld)

	if e.Consumable != nil && e.Consumable.L4Policy.RequiresConntrack() {
		opts[OptionConntrack] = "enabled"
	}

	if owner.EnableEndpointPolicyEnforcement(e) {
		opts[OptionPolicy] = "enabled"
	} else {
		opts[OptionPolicy] = "disabled"
	}

	e.Consumable.Mutex.RUnlock()
	repo.Mutex.RUnlock()

	optsChanged := e.applyOptsLocked(opts)

	// If we are in this function, then policy has been calculated.
	if !e.PolicyCalculated {
		e.getLogger().Debug("setting PolicyCalculated to true for endpoint")
		e.PolicyCalculated = true
		// Always trigger a regenerate after the first policy
		// calculation has been performed
		policyChanged = true
	}

	e.getLogger().WithFields(log.Fields{
		"policyChanged": policyChanged,
		"optsChanged":   optsChanged,
	}).Debug("Done regenerating")

	// If no policy change occurred for this endpoint then the endpoint is
	// already running the latest revision, otherwise we have to wait for
	// the regeneration of the endpoint to complete.
	if !policyChanged {
		e.policyRevision = revision
	} else {
		e.nextPolicyRevision = revision
	}

	return policyChanged || optsChanged, nil
}

// Called with e.Mutex locked
func (e *Endpoint) regenerate(owner Owner) error {
	e.BuildMutex.Lock()
	defer e.BuildMutex.Unlock()

	// If endpoint was marked as disconnected then
	// it won't be regenerated
	if e.IsDisconnecting() {
		e.getLogger().Debug("Endpoint disconnected, skipping build")
		return fmt.Errorf("endpoint disconnected, skipping build")
	}

	e.getLogger().Debug("Regenerating endpoint...")

	origDir := filepath.Join(owner.GetStateDir(), e.StringID())

	// This is the temporary directory to store the generated headers,
	// the original existing directory is not overwritten until the
	// entire generation process has succeeded.
	tmpDir := origDir + "_next"

	// Create temporary endpoint directory if it does not exist yet
	if err := os.MkdirAll(tmpDir, 0777); err != nil {
		return fmt.Errorf("Failed to create endpoint directory: %s", err)
	}

	e.Mutex.Lock()

	if e.Consumable != nil {
		// Regenerate policy and apply any options resulting in the
		// policy change.
		if _, err := e.regeneratePolicy(owner); err != nil {
			e.Mutex.Unlock()
			return fmt.Errorf("Unable to regenerate policy for '%s': %s",
				e.PolicyMap.String(), err)
		}
	}
	e.Mutex.Unlock()

	if err := e.regenerateBPF(owner, tmpDir); err != nil {
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

	e.getLogger().Info("Regenerated program of endpoint")

	return nil
}

// Regenerate forces the regeneration of endpoint programs & policy
func (e *Endpoint) Regenerate(owner Owner) <-chan bool {
	newReq := &Request{
		ID:           uint64(e.ID),
		MyTurn:       make(chan bool),
		Done:         make(chan bool),
		ExternalDone: make(chan bool),
	}

	go func(owner Owner, req *Request, e *Endpoint) {
		buildSuccess := true

		e.Mutex.Lock()
		// If endpoint was marked as disconnected then it won't be
		// regenerated
		if !e.IsDisconnectingLocked() {
			e.State = StateRegenerating
		}

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

			if err := e.regenerate(owner); err != nil {
				buildSuccess = false
				e.LogStatus(BPF, Failure, err.Error())
			} else {
				buildSuccess = true
				e.SetState(StateReady)
				e.LogStatusOK(BPF, "Successfully regenerated endpoint program")
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

// TriggerPolicyUpdates indicates that a policy change is likely to
// affect this endpoint. Will update all required endpoint configuration and
// state to reflect new policy and regenerate programs if required.
//
// Returns true if policy was changed and endpoints needs to be rebuilt
func (e *Endpoint) TriggerPolicyUpdates(owner Owner) (bool, error) {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	if e.Consumable == nil {
		return false, nil
	}

	changed, err := e.regeneratePolicy(owner)
	if err != nil {
		return changed, fmt.Errorf("%s: %s", e.StringID(), err)
	}

	return changed, err
}

func (e *Endpoint) SetIdentity(owner Owner, id *policy.Identity) {
	repo := owner.GetPolicyRepository()
	cache := policy.GetConsumableCache()

	repo.Mutex.Lock()
	defer repo.Mutex.Unlock()

	if e.Consumable != nil {
		if e.SecLabel != nil && id.ID == e.Consumable.ID {
			e.SecLabel = id
			e.Consumable.Mutex.Lock()
			e.Consumable.Labels = id
			e.Consumable.LabelArray = id.Labels.ToSlice()
			e.Consumable.Mutex.Unlock()
			return
		}
		cache.Remove(e.Consumable)
	}
	e.SecLabel = id
	e.LabelsHash = e.SecLabel.Labels.SHA256Sum()
	e.Consumable = cache.GetOrCreate(id.ID, id)

	if e.State == StateWaitingForIdentity {
		e.State = StateReady
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
