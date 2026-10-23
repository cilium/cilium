// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"fmt"
	"iter"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func (f *factory) SharedPolicyEnabled() bool {
	return f != nil && f.allocator != nil
}

// SyncEndpointOverlay syncs the policy rules for the given endpoint into the shared LPM trie
// and updates the overlay map. On failure, e.g. when the shared policy map is full, the
// endpoint keeps its current rule set.
func (f *factory) SyncEndpointOverlay(epID uint16, entries iter.Seq2[policyTypes.Key, policyTypes.MapStateEntry]) error {
	if f.allocator == nil {
		return nil
	}

	var sharedRules []ruleWithEntry
	for key, entry := range entries {
		sharedRules = append(sharedRules, ruleWithEntry{
			Key:   key,
			Entry: entry,
		})
	}

	// Update shared rules and their endpoint references together.
	_, _, err := f.updateEndpointRules(epID, sharedRules)
	if errors.Is(err, unix.ENOSPC) {
		return fmt.Errorf("failed to update rule set, shared policy map is full (see --%s): %w", PolicySharedMapMaxName, err)
	}
	if err != nil {
		return fmt.Errorf("failed to update rule set: %w", err)
	}

	return nil
}

// removeEndpointOverlay deletes the overlay entry and decrements ruleset refcount for the endpoint.
func (f *factory) removeEndpointOverlay(epID uint16) {
	if f.allocator == nil {
		return
	}

	a := f.allocator
	a.mu.Lock()
	defer a.mu.Unlock()

	if ruleSetID, ok := a.epToRuleSetID[epID]; ok {
		f.releaseRuleSetLocked(ruleSetID)
		delete(a.epToRuleSetID, epID)
	}
	_ = f.overlayMap.Delete(&OverlayKey{EndpointID: uint32(epID)})
}

// restoreSharedPolicyState recovers the full shared policy state from pinned BPF maps during agent startup.
// It iterates SharedPolicyMap to reconstruct ruleset definitions, links endpoints from PolicyOverlayMap,
// and purges any orphaned rulesets.
func (f *factory) restoreSharedPolicyState() error {
	if f.allocator == nil {
		return nil
	}

	// 1. Recover rulesets and their rules from SharedPolicyMap
	rulesByRuleSet := make(map[uint32][]sharedRule)
	err := f.sharedMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key, okK := k.(*SharedPolicyKey)
		val, okV := v.(*PolicyEntry)
		if okK && okV && key.RuleSetID > 0 {
			rulesByRuleSet[key.RuleSetID] = append(rulesByRuleSet[key.RuleSetID], sharedRule{
				Key:   *key,
				Entry: *val,
			})
		}
	})
	if err != nil {
		return fmt.Errorf("failed to dump shared policy map during recovery: %w", err)
	}

	for ruleSetID, rules := range rulesByRuleSet {
		f.allocator.restoreRuleSetWithRules(ruleSetID, rules)
	}

	// 2. Link endpoints from PolicyOverlayMap
	type overlayMapping struct {
		epID      uint16
		ruleSetID uint32
	}
	var overlayEntries []overlayMapping
	err = f.overlayMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key, okK := k.(*OverlayKey)
		val, okV := v.(*OverlayValue)
		if okK && okV && val.RuleSetID > 0 {
			overlayEntries = append(overlayEntries, overlayMapping{
				epID:      uint16(key.EndpointID),
				ruleSetID: val.RuleSetID,
			})
		}
	})
	if err != nil {
		return fmt.Errorf("failed to dump policy overlay map during recovery: %w", err)
	}

	for _, entry := range overlayEntries {
		if _, exists := rulesByRuleSet[entry.ruleSetID]; !exists {
			f.allocator.restoreRuleSetWithRules(entry.ruleSetID, nil)
		}
		f.linkEndpoint(entry.epID, entry.ruleSetID)
	}

	// 3. Clean up any unreferenced/orphaned rule sets from previous crashes or ungraceful terminations
	f.purgeOrphanedRuleSets()

	return nil
}

// DumpEndpointSharedEntries returns the realized shared policy map entries of the rule set
// currently assigned to the given endpoint in the overlay map, converted to the per-endpoint
// PolicyEntriesDump format. Returns nil if the endpoint has no overlay entry.
func (f *factory) DumpEndpointSharedEntries(epID uint16) (PolicyEntriesDump, error) {
	if f.allocator == nil {
		return nil, nil
	}

	v, err := f.overlayMap.Lookup(&OverlayKey{EndpointID: uint32(epID)})
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to look up overlay entry for endpoint %d: %w", epID, err)
	}
	overlay, ok := v.(*OverlayValue)
	if !ok {
		return nil, fmt.Errorf("unexpected overlay value type %T", v)
	}

	return dumpSharedRuleSetEntries(f.sharedMap, overlay.RuleSetID)
}

// HasEndpointOverlay reports whether the endpoint has an overlay entry, i.e. whether the
// datapath enforces the endpoint's policy from the shared policy map. Without an overlay
// entry the datapath uses the endpoint's per-endpoint policy map.
func (f *factory) HasEndpointOverlay(epID uint16) bool {
	if f.allocator == nil {
		return false
	}
	_, err := f.overlayMap.Lookup(&OverlayKey{EndpointID: uint32(epID)})
	return err == nil
}

// RemoveStaleEndpointOverlays removes the overlay entries and rule set references of
// endpoints for which 'exists' returns false, e.g. endpoints that were deleted while the
// agent was down. This is the shared policy map equivalent of removing the per-endpoint
// policy maps of such endpoints, so that an endpoint reusing the ID never sees the policy
// of the old endpoint.
func (f *factory) RemoveStaleEndpointOverlays(exists func(epID uint16) bool) error {
	if f.allocator == nil {
		return nil
	}

	var stale []uint16
	err := f.overlayMap.DumpWithCallback(func(k bpf.MapKey, _ bpf.MapValue) {
		if key, ok := k.(*OverlayKey); ok && !exists(uint16(key.EndpointID)) {
			stale = append(stale, uint16(key.EndpointID))
		}
	})
	if err != nil {
		return fmt.Errorf("failed to dump policy overlay map: %w", err)
	}
	for _, epID := range stale {
		f.removeEndpointOverlay(epID)
	}
	return nil
}

func (f *factory) registerSharedPolicy(lifecycle cell.Lifecycle, reg *registry.MapRegistry) {
	f.allocator = NewRuleSetAllocator()
	var shared, overlay *bpf.Map
	lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			var err error
			shared, err = bpf.NewMapFromRegistry(reg, SharedPolicyMapName, &SharedPolicyKey{}, &PolicyEntry{})
			if err != nil {
				return fmt.Errorf("create shared policy map: %w", err)
			}
			overlay, err = bpf.NewMapFromRegistry(reg, PolicyOverlayMapName, &OverlayKey{}, &OverlayValue{})
			if err != nil {
				return fmt.Errorf("create policy overlay map: %w", err)
			}
			if err := shared.OpenOrCreate(); err != nil {
				return fmt.Errorf("open shared policy map: %w", err)
			}
			if err := overlay.OpenOrCreate(); err != nil {
				return errors.Join(fmt.Errorf("open policy overlay map: %w", err), shared.Close())
			}
			f.sharedMap, f.overlayMap = shared, overlay
			f.allocator = NewRuleSetAllocator()

			f.logger.Info("Recovering shared policy state")
			if err := f.restoreSharedPolicyState(); err != nil {
				return errors.Join(err, overlay.Close(), shared.Close())
			}
			return nil
		},
		OnStop: func(cell.HookContext) error {
			return errors.Join(overlay.Close(), shared.Close())
		},
	})
}
