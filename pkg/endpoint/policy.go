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
)

func (e *Endpoint) checkEgressAccess(owner Owner, opts models.ConfigurationMap, dstID policy.NumericIdentity, opt string) {
	var err error

	ctx := policy.SearchContext{
		From: e.Consumable.LabelList,
	}

	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}

	ctx.To, err = owner.GetCachedLabelList(dstID)
	if err != nil {
		log.Warningf("Unable to get label list for ID %d, access for endpoint may be restricted\n", dstID)
		return
	}

	switch owner.GetPolicyTree().AllowsRLocked(&ctx) {
	case api.ACCEPT, api.ALWAYS_ACCEPT:
		opts[opt] = "enabled"
	case api.DENY:
		opts[opt] = "disabled"
	}
}

// allowConsumer must be called with endpointsMU held
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
		return nil
	}

	log.Debugf("Evaluating policy for %+v", ctx)

	decision := owner.GetPolicyTree().AllowsRLocked(ctx)
	if decision == api.ACCEPT {
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

// proxyID returns a unique string to identify a proxy mapping
func (e *Endpoint) proxyID(l4 *policy.L4Filter) string {
	return fmt.Sprintf("%d:%s:%d", e.ID, l4.Protocol, l4.Port)
}

func (e *Endpoint) addRedirect(owner Owner, l4 *policy.L4Filter) (uint16, error) {
	proxy := owner.GetProxy()
	if proxy == nil {
		return 0, fmt.Errorf("can't redirect, proxy disabled")
	}

	log.Debugf("Adding redirect %+v to endpoint %d", l4, e.ID)
	r, err := proxy.CreateOrUpdateRedirect(l4, e.proxyID(l4), e)
	if err != nil {
		return 0, err
	}

	return r.ToPort, nil
}

func (e *Endpoint) removeRedirect(owner Owner, l4 *policy.L4Filter) error {
	proxy := owner.GetProxy()
	if proxy == nil {
		return nil
	}

	id := e.proxyID(l4)
	log.Debugf("Removing redirect %s from endpoint %d", id, e.ID)
	return proxy.RemoveRedirect(id)
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
			if err := e.removeRedirect(owner, &v); err != nil {
				log.Warningf("error while removing proxy: %s", err)
			}
		}
	}
}

// Must be called with endpointsMU held
func (e *Endpoint) regenerateConsumable(owner Owner) (bool, error) {
	c := e.Consumable

	// Containers without a security label are not accessible
	if c.ID == 0 {
		log.Fatalf("BUG: Endpoints lacks identity")
		return false, nil
	}

	cache := owner.GetConsumableCache()

	// Skip if policy for this consumable is already valid
	//if c.Iteration == cache.Iteration {
	//	tree.Mutex.RUnlock()
	//	log.Debugf("Reusing cached policy for identity %d", c.ID)
	//	return false, nil
	//}

	maxID, err := owner.GetCachedMaxLabelID()
	if err != nil {
		return false, err
	}

	c.Mutex.RLock()
	ctx := policy.SearchContext{
		To: c.LabelList,
	}
	c.Mutex.RUnlock()

	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}

	tree := owner.GetPolicyTree()
	tree.Mutex.Lock()
	newL4policy := tree.ResolveL4Policy(&ctx)
	defer tree.Mutex.Unlock()

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

	if newL4policy.HasRedirect() {
		log.Debugf("Endpoint %d interacts with proxy, allowing localhost", e.ID)
		e.allowConsumer(owner, policy.ID_HOST)
	}

	// Check access from reserved consumables first
	reservedIDs := cache.GetReservedIDs()
	for _, id := range reservedIDs {
		if err := e.evaluateConsumerSource(owner, &ctx, id); err != nil {
			// This should never really happen
			// FIXME: clear policy because it is inconsistent
			log.Debugf("Received error while evaluating policy: %s", err)
		}
	}

	// Iterate over all possible assigned search contexts
	idx := policy.MinimalNumericIdentity
	log.Debugf("Policy eval from %+v to %+v", idx, maxID)
	for idx < maxID {
		if err := e.evaluateConsumerSource(owner, &ctx, idx); err != nil {
			// FIXME: clear policy because it is inconsistent
			log.Debugf("Received error while evaluating policy: %s", err)
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
	c.Iteration = cache.GetIteration()

	log.Debugf("New policy (iteration %d) for consumable %d: %+v\n", c.Iteration, c.ID, c.Consumers)

	// FIXME: Optimize this and only return true if L4 policy changed
	return true, nil
}

func (e *Endpoint) regeneratePolicy(owner Owner) (bool, error) {
	policyChanged, err := e.regenerateConsumable(owner)
	if err != nil {
		return false, err
	}

	opts := make(models.ConfigurationMap)
	tree := owner.GetPolicyTree()
	tree.Mutex.RLock()
	e.Consumable.Mutex.RLock()

	e.checkEgressAccess(owner, opts, policy.ID_HOST, OptionAllowToHost)
	e.checkEgressAccess(owner, opts, policy.ID_WORLD, OptionAllowToWorld)

	if e.Consumable != nil && e.Consumable.L4Policy.RequiresConntrack() {
		opts[OptionConntrack] = "enabled"
	}

	e.Consumable.Mutex.RUnlock()
	tree.Mutex.RUnlock()

	optsChanged := e.ApplyOptsLocked(opts)

	if !e.PolicyCalculated {
		e.PolicyCalculated = true
		// Always trigger a regenerate after the first policy
		// calculation has been performed
		policyChanged = true
	}

	return policyChanged || optsChanged, nil
}

func (e *Endpoint) regenerate(owner Owner) error {
	origDir := filepath.Join(".", e.StringIDLocked())

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
	go func(e *Endpoint, myTurn <-chan bool, finish chan<- bool, externalFinish chan<- bool) {
		buildSuccess := true
		e.Mutex.Lock()
		e.State = StateRegenerating
		eID := e.ID
		e.Mutex.Unlock()
		isMyTurn, isMyTurnChanOK := <-myTurn
		if isMyTurnChanOK && isMyTurn {
			log.Debugf("Finally, is my turn to regenerate myself [%d]", eID)
			e.Mutex.Lock()
			err := e.regenerate(owner)
			e.State = StateReady
			e.Mutex.Unlock()
			if err != nil {
				buildSuccess = false
				e.LogStatus(BPF, Failure, err.Error())
			} else {
				buildSuccess = true
				e.LogStatusOK(BPF, "Successfully regenerated endpoint program")
			}
			finish <- buildSuccess
		} else {
			buildSuccess = false
			log.Debugf("My request was canceled because I'm already in line [%d]", eID)
		}
		// The external listener can ignore the channel so we need to
		// make sure we don't block
		select {
		case externalFinish <- buildSuccess:
		default:
		}
		close(externalFinish)
	}(e, newReq.MyTurn, newReq.Done, newReq.ExternalDone)
	return newReq.ExternalDone
}

// TriggerPolicyUpdates indicates that a policy change is likely to
// affect this endpoint. Will update all required endpoint configuration and
// state to reflect new policy and regenerate programs if required.
func (e *Endpoint) TriggerPolicyUpdates(owner Owner) (bool, error) {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	if e.Consumable == nil {
		return false, nil
	}
	return e.regeneratePolicy(owner)
}

func (e *Endpoint) SetIdentity(owner Owner, id *policy.Identity) {
	tree := owner.GetPolicyTree()
	tree.Mutex.Lock()
	defer tree.Mutex.Unlock()
	cache := owner.GetConsumableCache()

	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	if e.Consumable != nil {
		if e.SecLabel != nil && id.ID == e.Consumable.ID {
			e.SecLabel = id
			e.Consumable.Mutex.Lock()
			e.Consumable.Labels = id
			e.Consumable.LabelList = id.Labels.ToSlice()
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
