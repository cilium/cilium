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
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	log "github.com/Sirupsen/logrus"
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
		log.Warningf("Unable to get label list for ID %d, access for endpoint may be restricted\n", dstID)
		return
	}

	switch owner.GetPolicyRepository().AllowsRLocked(&ctx) {
	case api.Allowed:
		opts[opt] = "enabled"
	case api.Denied:
		opts[opt] = "disabled"
	}
}

// allowConsumer must be called with global endpoint.Mutex held
func (e *Endpoint) allowConsumer(owner Owner, id policy.NumericIdentity) {
	cache := owner.GetConsumableCache()
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
		log.Debugf("[%s] Ignoring unused ID %v", e.PolicyID(), ctx)
		return nil
	}

	log.Debugf("[%s] Evaluating context %+v", e.PolicyID(), ctx)

	if owner.GetPolicyRepository().AllowsRLocked(ctx) == api.Allowed {
		e.allowConsumer(owner, srcID)
	}

	return nil
}

func (e *Endpoint) invalidatePolicy() {
	if e.Consumable != nil {
		// Resetting to 0 will trigger a regeneration on the next update
		log.Debugf("Invalidated policy for endpoint %d", e.ID)
		e.Consumable.Mutex.Lock()
		e.Consumable.Iteration = 0
		e.Consumable.Mutex.Unlock()
	}
}

// ProxyID returns a unique string to identify a proxy mapping
func (e *Endpoint) ProxyID(l4 *policy.L4Filter) string {
	return fmt.Sprintf("%d:%s:%d", e.ID, l4.Protocol, l4.Port)
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

		if v.L7Parser != "" {
			if err := owner.RemoveProxyRedirect(e, &v); err != nil {
				log.Warningf("error while removing proxy: %s", err)
			}
		}
	}
}

// Must be called with global endpoint.Mutex held
func (e *Endpoint) regenerateConsumable(owner Owner) (bool, error) {
	c := e.Consumable

	// Containers without a security label are not accessible
	if c.ID == 0 {
		log.Fatalf("[%s] BUG: Endpoints lacks identity", e.PolicyID())
		return false, nil
	}

	cache := owner.GetConsumableCache()

	// Skip if policy for this consumable is already valid
	//if c.Iteration == cache.Iteration {
	//	repo.Mutex.RUnlock()
	//	log.Debugf("Reusing cached policy for identity %d", c.ID)
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
	newL4policy := repo.ResolveL4Policy(&ctx)
	defer repo.Mutex.Unlock()

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

	c.L4Policy = newL4policy

	if newL4policy.HasRedirect() || owner.AlwaysAllowLocalhost() {
		e.allowConsumer(owner, policy.ID_HOST)
	}

	// Check access from reserved consumables first
	reservedIDs := cache.GetReservedIDs()
	for _, id := range reservedIDs {
		if err := e.evaluateConsumerSource(owner, &ctx, id); err != nil {
			// This should never really happen
			// FIXME: clear policy because it is inconsistent
			log.Debugf("[%s] Received error while evaluating policy: %s",
				e.PolicyID(), err)
		}
	}

	// Iterate over all possible assigned search contexts
	idx := policy.MinimalNumericIdentity
	log.Debugf("[%s] Eval ID range %+v-%+v", e.PolicyID(), idx, maxID)
	for idx < maxID {
		if err := e.evaluateConsumerSource(owner, &ctx, idx); err != nil {
			// FIXME: clear policy because it is inconsistent
			log.Debugf("[%s] Received error while evaluating policy: %s",
				e.PolicyID(), err)
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

	log.Debugf("[%s] Iteration %d: new consumable %d, consumers = %+v\n",
		e.PolicyID(), c.Iteration, c.ID, c.Consumers)

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
	repo.Mutex.Unlock()
	c.Mutex.RUnlock()

	e.L3Policy = newL3policy

	// FIXME: Optimize this and only return true if L3 policy changed
	return true, nil
}

// Only called when e.Consumable != nil.
func (e *Endpoint) regeneratePolicy(owner Owner) (bool, error) {
	log.Debugf("[%s] Starting regenerate...", e.PolicyID())

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
	e.Consumable.Mutex.RLock()

	e.checkEgressAccess(owner, opts, policy.ID_HOST, OptionAllowToHost)
	e.checkEgressAccess(owner, opts, policy.ID_WORLD, OptionAllowToWorld)

	if e.Consumable != nil && e.Consumable.L4Policy.RequiresConntrack() {
		opts[OptionConntrack] = "enabled"
	}

	if owner.UpdateEndpointPolicyEnforcement(e) {
		opts[OptionPolicy] = "enabled"
	} else {
		opts[OptionPolicy] = "disabled"
	}

	e.Consumable.Mutex.RUnlock()
	repo.Mutex.RUnlock()

	optsChanged := e.ApplyOptsLocked(opts)

	if !e.PolicyCalculated {
		e.PolicyCalculated = true
		// Always trigger a regenerate after the first policy
		// calculation has been performed
		policyChanged = true
	}

	log.Debugf("[%s] Done regenerating policyChanged=%v optsChanged=%v",
		e.PolicyID(), policyChanged, optsChanged)

	return policyChanged || optsChanged, nil
}

func (e *Endpoint) regenerate(owner Owner) error {
	origDir := filepath.Join(".", e.StringID())

	// This is the temporary directory to store the generated headers,
	// the original existing directory is not overwritten until the
	// entire generation process has succeeded.
	tmpDir := origDir + "_next"

	// Create temporary endpoint directory if it does not exist yet
	if err := os.MkdirAll(tmpDir, 0777); err != nil {
		return fmt.Errorf("Failed to create endpoint directory: %s", err)
	}

	if e.Consumable != nil {
		// Regenerate policy and apply any options resulting in the
		// policy change.
		if _, err := e.regeneratePolicy(owner); err != nil {
			return fmt.Errorf("Unable to regenerate policy for '%s': %s",
				e.PolicyMap.String(), err)
		}
	}

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
			log.Warningf("Restoring directory %s for endpoint "+
				"%s failed, endpoint is in inconsistent state. Keeping stale directory.",
				backupDir, e.String())
			return err2
		}

		return fmt.Errorf("Restored original endpoint directory, atomic replace failed: %s", err)
	}

	os.RemoveAll(backupDir)

	log.Infof("Regenerated program of endpoint %d", e.ID)

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
	owner.QueueEndpointBuild(newReq)
	go func(req *Request, e *Endpoint) {
		buildSuccess := true

		e.Mutex.Lock()
		// If endpoint was marked as disconnected then
		// it won't be regenerated
		if e.State != StateDisconnected {
			e.State = StateRegenerating
		}
		eID := e.ID
		e.Mutex.Unlock()

		isMyTurn, isMyTurnChanOK := <-req.MyTurn
		if isMyTurnChanOK && isMyTurn {
			log.Debugf("it is now [%d]'s turn to regenerate", eID)
			e.Mutex.Lock()
			var err error

			// If endpoint was marked as disconnected then
			// it won't be regenerated
			if e.State != StateDisconnected {
				log.Debugf("Regenerating... [%d]", eID)
				err = e.regenerate(owner)
				e.State = StateReady
			} else {
				log.Debugf("Endpoint disconnected %d", e.ID)
				err = fmt.Errorf("Endpoint disconnected")
			}
			e.Mutex.Unlock()

			if err != nil {
				buildSuccess = false
				e.LogStatus(BPF, Failure, err.Error())
			} else {
				buildSuccess = true
				e.LogStatusOK(BPF, "Successfully regenerated endpoint program")
			}

			req.Done <- buildSuccess
		} else {
			buildSuccess = false
			log.Debugf("My request was canceled because I'm already in line [%d]", eID)
		}
		// The external listener can ignore the channel so we need to
		// make sure we don't block
		select {
		case req.ExternalDone <- buildSuccess:
		default:
		}
		close(req.ExternalDone)
	}(newReq, e)
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
	cache := owner.GetConsumableCache()

	e.Mutex.Lock()
	defer e.Mutex.Unlock()

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
	e.Consumable = cache.GetOrCreate(id.ID, id)

	if e.State == StateWaitingForIdentity {
		e.State = StateReady
	}

	e.Consumable.Mutex.RLock()
	log.Debugf("Set identity of EP %d to %d and consumable to %+v", e.ID, id, e.Consumable)
	e.Consumable.Mutex.RUnlock()
}
