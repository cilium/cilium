// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (f *factory) updateOverlayPolicyEntryLocked(epID uint16, ruleSetID uint32) error {
	key := OverlayKey{EndpointID: uint32(epID)}
	value := OverlayValue{RuleSetID: ruleSetID}
	return f.overlayMap.Update(&key, &value)
}

// updateEndpointRules makes the endpoint use a rule set with the given rules: a rule set with
// the same rules if there is one, else its current rule set updated in place if no other
// endpoint uses it, else a new rule set. On error, the endpoint keeps its current rule set.
func (f *factory) updateEndpointRules(epID uint16, rules []ruleWithEntry) (uint32, bool, error) {
	a := f.allocator
	newHash := computeRuleSetHashFromEntries(rules)

	a.mu.Lock()
	defer a.mu.Unlock()

	f.deletePendingRuleSetsLocked()

	oldRuleSetID, hadOld := a.epToRuleSetID[epID]

	// Case 1: Exact hash match exists
	if existingID, ok := a.rulesets[newHash]; ok {
		if existingID == oldRuleSetID {
			return existingID, false, f.updateOverlayPolicyEntryLocked(epID, existingID)
		}
		if err := f.updateOverlayPolicyEntryLocked(epID, existingID); err != nil {
			return 0, false, err
		}
		a.byID[existingID].refcount++
		a.epToRuleSetID[epID] = existingID
		if hadOld {
			f.releaseRuleSetLocked(oldRuleSetID)
		}
		return existingID, false, nil
	}

	// Case 2: Update the rule set in place if no other endpoint uses it.
	if entry := a.byID[oldRuleSetID]; hadOld && entry != nil && entry.refcount == 1 {
		newSharedRules := convertToSharedRules(oldRuleSetID, rules)
		entries, err := f.writeRuleSetLocked(entry.rules, newSharedRules)
		if err == nil {
			a.setRulesLocked(oldRuleSetID, entry, entries, newHash)
			return oldRuleSetID, true, f.updateOverlayPolicyEntryLocked(epID, oldRuleSetID)
		}
		// Keep track of the entries left in the map, and use a new rule set instead.
		a.setRulesLocked(oldRuleSetID, entry, entries, computeRuleSetHashFromSharedRules(entries))
		id, allocErr := f.allocateNewRuleSetLocked(epID, rules, newHash, hadOld, oldRuleSetID)
		if allocErr != nil {
			return 0, false, errors.Join(err, allocErr)
		}
		return id, false, nil
	}

	// Case 3: Fallback - allocate new rule set
	id, err := f.allocateNewRuleSetLocked(epID, rules, newHash, hadOld, oldRuleSetID)
	return id, false, err
}

// allocateNewRuleSetLocked writes the rules to a new rule set and switches the endpoint to it.
func (f *factory) allocateNewRuleSetLocked(epID uint16, rules []ruleWithEntry, hash ruleSetKey, hadOld bool, oldRuleSetID uint32) (uint32, error) {
	a := f.allocator
	ruleSetID, err := a.nextIDLocked()
	if err != nil {
		return 0, err
	}
	entry := &ruleSetEntry{}
	a.byID[ruleSetID] = entry

	entries, err := f.writeRuleSetLocked(nil, convertToSharedRules(ruleSetID, rules))
	entry.rules = entries
	if err != nil {
		f.deleteRuleSetLocked(ruleSetID, entry)
		return 0, fmt.Errorf("failed to write shared rules: %w", err)
	}

	// Update overlay map in eBPF datapath first before releasing old ruleset
	if err := f.updateOverlayPolicyEntryLocked(epID, ruleSetID); err != nil {
		f.deleteRuleSetLocked(ruleSetID, entry)
		return 0, fmt.Errorf("failed to update overlay entry: %w", err)
	}

	a.setRulesLocked(ruleSetID, entry, entries, hash)
	entry.refcount = 1
	a.epToRuleSetID[epID] = ruleSetID

	if hadOld {
		f.releaseRuleSetLocked(oldRuleSetID)
	}

	return ruleSetID, nil
}

// releaseRuleSetLocked drops an endpoint's reference to a rule set, and deletes the rule set
// when no endpoint uses it anymore.
func (f *factory) releaseRuleSetLocked(id uint32) {
	entry := f.allocator.byID[id]
	if entry == nil || entry.refcount == 0 {
		return
	}

	entry.refcount--
	if entry.refcount == 0 {
		f.deleteRuleSetLocked(id, entry)
	}
}

// deleteRuleSetLocked deletes the entries of a rule set that no endpoint uses, and frees its
// ID. If some entries can't be deleted, the rule set keeps track of them and its ID is not
// reused until they are deleted, which is retried on the next update.
func (f *factory) deleteRuleSetLocked(id uint32, entry *ruleSetEntry) {
	a := f.allocator
	if a.rulesets[entry.hash] == id {
		delete(a.rulesets, entry.hash)
	}
	entry.hash = ""

	entries, err := f.writeRuleSetLocked(entry.rules, nil)
	entry.rules = entries
	if err != nil {
		if _, pending := a.pendingDelete[id]; !pending {
			f.logger.Warn("Failed to delete unused shared policy rule set, will retry",
				logfields.ID, id,
				logfields.Error, err,
			)
		}
		a.pendingDelete[id] = struct{}{}
		return
	}

	delete(a.pendingDelete, id)
	delete(a.byID, id)
	a.freeIDs = append(a.freeIDs, id)
}

// deletePendingRuleSetsLocked retries deleting unused rule sets that could not be deleted
// before.
func (f *factory) deletePendingRuleSetsLocked() {
	a := f.allocator
	for id := range a.pendingDelete {
		f.deleteRuleSetLocked(id, a.byID[id])
	}
}

// writeRuleSetLocked changes the entries of a rule set in the shared policy map from 'old' to
// 'new', and returns the entries that are in the map afterwards. New and changed entries are
// written before obsolete entries are deleted, so that the datapath doesn't see transient
// drops. If writing an entry fails, the entries written so far are reverted and nothing is
// deleted. If deleting an entry fails, the other obsolete entries are still deleted. Either
// way, the returned entries include every entry of the rule set that is left in the map.
func (f *factory) writeRuleSetLocked(old, new []sharedRule) ([]sharedRule, error) {
	m := f.sharedMap
	added, removed, modified := diffSharedRules(old, new)

	for i, r := range added {
		if err := m.Update(&r.Key, &r.Entry); err != nil {
			entries, revertErr := f.revertRuleSetLocked(old, added[:i], nil)
			return entries, errors.Join(fmt.Errorf("failed to insert new rule: %w", err), revertErr)
		}
	}

	for i, mod := range modified {
		if err := m.Update(&mod.new.Key, &mod.new.Entry); err != nil {
			entries, revertErr := f.revertRuleSetLocked(old, added, modified[:i])
			return entries, errors.Join(fmt.Errorf("failed to update modified rule: %w", err), revertErr)
		}
	}

	var left []sharedRule
	var errs error
	for _, r := range removed {
		if err := deleteSharedEntry(m, &r.Key); err != nil {
			left = append(left, r)
			errs = errors.Join(errs, err)
		}
	}
	if errs != nil {
		return append(slices.Clone(new), left...), fmt.Errorf("failed to delete obsolete rules: %w", errs)
	}

	return new, nil
}

// revertRuleSetLocked reverts added and modified entries of a rule set back to 'old', and
// returns the entries that are in the map afterwards: 'old', and any entry that could not be
// reverted.
func (f *factory) revertRuleSetLocked(old, added []sharedRule, modified []modifiedRule) ([]sharedRule, error) {
	m := f.sharedMap
	entries := slices.Clone(old)
	var errs error

	for _, mod := range modified {
		if err := m.Update(&mod.old.Key, &mod.old.Entry); err != nil {
			if i := slices.IndexFunc(entries, func(r sharedRule) bool { return r.Key == mod.old.Key }); i >= 0 {
				entries[i] = mod.new
			}
			errs = errors.Join(errs, err)
		}
	}

	for _, r := range added {
		if err := deleteSharedEntry(m, &r.Key); err != nil {
			entries = append(entries, r)
			errs = errors.Join(errs, err)
		}
	}

	if errs != nil {
		return entries, fmt.Errorf("failed to revert rules: %w", errs)
	}
	return entries, nil
}

// deleteSharedEntry deletes an entry from the shared policy map. An entry that does not
// exist is not an error.
func deleteSharedEntry(m policyBPFMap, key *SharedPolicyKey) error {
	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}
