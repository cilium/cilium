// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
)

func (f *factory) updateOverlayPolicyEntryLocked(epID uint16, ruleSetID uint32) error {
	key := OverlayKey{EndpointID: uint32(epID)}
	value := OverlayValue{RuleSetID: ruleSetID}
	return f.overlayMap.Update(&key, &value)
}

// updateEndpointRules performs incremental updates when possible.
func (f *factory) updateEndpointRules(epID uint16, rules []ruleWithEntry) (uint32, bool, error) {
	a := f.allocator
	newHash := computeRuleSetHashFromEntries(rules)

	a.mu.Lock()
	defer a.mu.Unlock()

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

	// Case 2: Check if we can update in-place (sole owner)
	if hadOld {
		if entry := a.byID[oldRuleSetID]; entry != nil && entry.refcount == 1 && entry.rules != nil {
			newSharedRules := convertToSharedRules(oldRuleSetID, rules)

			added, removed, modified := diffSharedRules(entry.rules, newSharedRules)

			if len(added) > 0 || len(removed) > 0 || len(modified) > 0 {
				if err := f.applyIncrementalUpdateLocked(added, removed, modified); err != nil {
					return f.allocateNewRuleSetLocked(epID, rules, newHash, hadOld, oldRuleSetID)
				}

				delete(a.rulesets, entry.hash)
				a.rulesets[newHash] = oldRuleSetID
				entry.hash = newHash
				entry.rules = newSharedRules

				return oldRuleSetID, true, f.updateOverlayPolicyEntryLocked(epID, oldRuleSetID)
			}
			return oldRuleSetID, false, f.updateOverlayPolicyEntryLocked(epID, oldRuleSetID)
		}
	}

	// Case 3: Fallback - allocate new rule set
	return f.allocateNewRuleSetLocked(epID, rules, newHash, hadOld, oldRuleSetID)
}

func (f *factory) allocateNewRuleSetLocked(epID uint16, rules []ruleWithEntry, hash ruleSetKey, hadOld bool, oldRuleSetID uint32) (uint32, bool, error) {
	a := f.allocator
	ruleSetID, err := a.nextIDLocked()
	if err != nil {
		return 0, false, err
	}

	sharedRules := convertToSharedRules(ruleSetID, rules)

	m := f.sharedMap
	for i, r := range sharedRules {
		if err := m.Update(&r.Key, &r.Entry); err != nil {
			for j := range i {
				_ = m.Delete(&sharedRules[j].Key)
			}
			a.freeIDs = append(a.freeIDs, ruleSetID)
			return 0, false, fmt.Errorf("failed to write shared rules: %w", err)
		}
	}

	// Update overlay map in eBPF datapath first before releasing old ruleset
	if err := f.updateOverlayPolicyEntryLocked(epID, ruleSetID); err != nil {
		for _, r := range sharedRules {
			_ = m.Delete(&r.Key)
		}
		a.freeIDs = append(a.freeIDs, ruleSetID)
		return 0, false, fmt.Errorf("failed to update overlay entry: %w", err)
	}

	a.rulesets[hash] = ruleSetID
	a.byID[ruleSetID] = &ruleSetEntry{
		hash:     hash,
		rules:    sharedRules,
		refcount: 1,
	}
	a.epToRuleSetID[epID] = ruleSetID

	if hadOld {
		f.releaseRuleSetLocked(oldRuleSetID)
	}

	return ruleSetID, false, nil
}

func (f *factory) releaseRuleSetLocked(id uint32) {
	a := f.allocator
	entry, exists := a.byID[id]
	if !exists || entry.refcount == 0 {
		return
	}

	entry.refcount--
	if entry.refcount == 0 {
		delete(a.rulesets, entry.hash)
		f.deleteRuleSetLocked(id, entry.rules)
		delete(a.byID, id)
		a.freeIDs = append(a.freeIDs, id)
	}
}

func (f *factory) deleteRuleSetLocked(id uint32, rules []sharedRule) {
	m := f.sharedMap
	if len(rules) > 0 {
		for _, r := range rules {
			_ = m.Delete(&r.Key)
		}
	} else {
		// Fallback: iterate shared policy map and remove any entries matching id
		var toDelete []bpf.MapKey
		_ = m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
			if key, ok := k.(*SharedPolicyKey); ok && key.RuleSetID == id {
				toDelete = append(toDelete, key)
			}
		})
		for _, key := range toDelete {
			_ = m.Delete(key)
		}
	}
}

// applyIncrementalUpdateLocked updates a rule set in place. If this fails, e.g. because the
// shared policy map is full, the changes already made are reverted so that the rule set is
// left as it was.
func (f *factory) applyIncrementalUpdateLocked(added, removed []sharedRule, modified []modifiedRule) error {
	m := f.sharedMap

	// Add new rules first to prevent transient drops
	for i, r := range added {
		if err := m.Update(&r.Key, &r.Entry); err != nil {
			for _, a := range added[:i] {
				_ = m.Delete(&a.Key)
			}
			return fmt.Errorf("failed to insert new rule: %w", err)
		}
	}

	// Update modified rules
	for i, mod := range modified {
		if err := m.Update(&mod.new.Key, &mod.new.Entry); err != nil {
			for _, p := range modified[:i] {
				_ = m.Update(&p.old.Key, &p.old.Entry)
			}
			for _, a := range added {
				_ = m.Delete(&a.Key)
			}
			return fmt.Errorf("failed to update modified rule: %w", err)
		}
	}

	// Delete obsolete rules last
	for _, r := range removed {
		_ = m.Delete(&r.Key)
	}

	return nil
}

// purgeOrphanedRuleSets removes rulesets that have no endpoints referencing them.
func (f *factory) purgeOrphanedRuleSets() {
	a := f.allocator
	a.mu.Lock()
	defer a.mu.Unlock()

	var orphaned []uint32
	for id, entry := range a.byID {
		if entry.refcount == 0 {
			orphaned = append(orphaned, id)
		}
	}

	for _, id := range orphaned {
		entry := a.byID[id]
		delete(a.rulesets, entry.hash)
		f.deleteRuleSetLocked(id, entry.rules)
		delete(a.byID, id)
		a.freeIDs = append(a.freeIDs, id)
	}
}

// linkEndpoint explicitly tracks which rule set an endpoint is using.
func (f *factory) linkEndpoint(epID uint16, ruleSetID uint32) {
	a := f.allocator
	a.mu.Lock()
	defer a.mu.Unlock()
	if oldID, hadOld := a.epToRuleSetID[epID]; hadOld {
		if oldID == ruleSetID {
			return
		}
		if oldEntry := a.byID[oldID]; oldEntry != nil && oldEntry.refcount > 0 {
			f.releaseRuleSetLocked(oldID)
		}
	}

	entry, exists := a.byID[ruleSetID]
	if !exists {
		placeholderHash := ruleSetKey(fmt.Sprintf("restored:%d", ruleSetID))
		a.rulesets[placeholderHash] = ruleSetID
		entry = &ruleSetEntry{
			hash:     placeholderHash,
			refcount: 0,
		}
		a.byID[ruleSetID] = entry
	}

	if ruleSetID >= a.nextRuleSetID {
		a.nextRuleSetID = ruleSetID + 1
	}

	a.epToRuleSetID[epID] = ruleSetID
	entry.refcount++
}
