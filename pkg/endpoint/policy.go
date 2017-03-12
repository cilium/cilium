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

	switch owner.GetPolicyTree().Allows(&ctx) {
	case policy.ACCEPT, policy.ALWAYS_ACCEPT:
		opts[opt] = "enabled"
	case policy.DENY:
		opts[opt] = "disabled"
	}
}

func (e *Endpoint) evaluateConsumerSource(owner Owner, ctx *policy.SearchContext, srcID policy.NumericIdentity) error {
	var err error

	c := e.Consumable
	ctx.From, err = owner.GetCachedLabelList(srcID)
	if err != nil {
		return err
	}

	// Skip currently unused IDs
	if ctx.From == nil || len(ctx.From) == 0 {
		return nil
	}

	log.Debugf("Evaluating policy for %+v", ctx)

	decision := owner.GetPolicyTree().Allows(ctx)
	// Only accept rules get stored
	if decision == policy.ACCEPT {
		cache := owner.GetConsumableCache()
		if !e.Opts.IsEnabled(OptionConntrack) {
			c.AllowConsumerAndReverse(cache, srcID)
		} else {
			c.AllowConsumer(cache, srcID)
		}
	}

	return nil
}

func (e *Endpoint) InvalidatePolicy() {
	if e.Consumable != nil {
		// Resetting to 0 will trigger a regeneration on the next update
		log.Debugf("Invalidated policy for endpoint %d", e.ID)
		e.Consumable.Iteration = 0
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

	tree := owner.GetPolicyTree()
	tree.Mutex.RLock()
	cache := owner.GetConsumableCache()

	// Skip if policy for this consumable is already valid
	if c.Iteration == cache.Iteration {
		tree.Mutex.RUnlock()
		log.Debugf("Reusing cached policy for identity %d", c.ID)
		return false, nil
	}
	tree.Mutex.RUnlock()

	// FIXME: Move to outer loops to avoid refetching
	maxID, err := owner.GetMaxLabelID()
	if err != nil {
		return false, err
	}

	ctx := policy.SearchContext{
		To: c.LabelList,
	}

	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}

	// Mark all entries unused by denying them
	for k := range c.Consumers {
		c.Consumers[k].DeletionMark = true
	}

	tree.Mutex.RLock()
	newL4policy := tree.ResolveL4Policy(&ctx)
	c.L4Policy = newL4policy

	// Check access from reserved consumables first
	for _, id := range cache.Reserved {
		if err := e.evaluateConsumerSource(owner, &ctx, id.ID); err != nil {
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
	tree.Mutex.RUnlock()

	// Garbage collect all unused entries
	for _, val := range c.Consumers {
		if val.DeletionMark {
			val.DeletionMark = false
			c.BanConsumer(val.ID)
		}
	}

	// Result is valid until cache iteration advances
	c.Iteration = cache.Iteration

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
	e.checkEgressAccess(owner, opts, policy.ID_HOST, OptionAllowToHost)
	e.checkEgressAccess(owner, opts, policy.ID_WORLD, OptionAllowToWorld)

	// L4 policy requires connection tracking
	if e.Consumable != nil && e.Consumable.L4Policy != nil {
		opts[OptionConntrack] = "enabled"
	}

	optsChanged := e.ApplyOpts(opts)

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

// Force regeneration of endpoint programs & policy
func (e *Endpoint) regenerateLocked(owner Owner) error {
	err := e.regenerate(owner)
	if err != nil {
		e.LogStatus(Failure, err.Error())
	} else {
		e.LogStatusOK("Successfully regenerated endpoint program")
	}

	return err
}

// Force regeneration of endpoint programs & policy
func (e *Endpoint) Regenerate(owner Owner) error {
	return e.regenerateLocked(owner)
}

// Called to indicate that a policy change is likely to affect this endpoint.
// Will update all required endpoint configuration and state to reflect new
// policy and regenerate programs if required.
func (e *Endpoint) TriggerPolicyUpdates(owner Owner) error {
	if e.Consumable == nil {
		return nil
	}

	optionChanges, err := e.regeneratePolicy(owner)
	if err != nil {
		return err
	}

	if optionChanges {
		return e.regenerateLocked(owner)
	}

	return nil
}

func (e *Endpoint) SetIdentity(owner Owner, id *policy.Identity) {
	tree := owner.GetPolicyTree()
	tree.Mutex.Lock()
	defer tree.Mutex.Unlock()
	cache := owner.GetConsumableCache()

	if e.Consumable != nil {
		if e.SecLabel != nil && id.ID == e.Consumable.ID {
			e.SecLabel = id
			e.Consumable.Labels = id
			return
		}
		cache.Remove(e.Consumable)
	}
	e.SecLabel = id
	e.Consumable = cache.GetOrCreate(id.ID, id)

	if e.State == StateWaitingForIdentity {
		e.State = StateReady
	}

	log.Debugf("Set identity of EP %d to %d and consumable to %+v", e.ID, id, e.Consumable)
}
