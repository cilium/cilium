// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"iter"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

type sharedManager struct {
	allocator *RuleSetAllocator
}

var (
	sharedMgrOnce sync.Once
	sharedMgr     *sharedManager
)

// SharedManagerEnabled reports whether the shared policy map lookup path is enabled.
func SharedManagerEnabled() bool {
	return option.Config.EnableSharedPolicy
}

// InitSharedManager initializes the shared manager with a custom maxRuleSets capacity.
func InitSharedManager(maxRuleSets uint32) {
	sharedMgrOnce.Do(func() {
		sharedMgr = &sharedManager{
			allocator: NewRuleSetAllocator(WithMaxRuleSets(maxRuleSets)),
		}
	})
}

func getSharedManager() *sharedManager {
	InitSharedManager(uint32(DefaultPolicyConfig.BpfPolicyMaxRuleSets))
	return sharedMgr
}

// SyncEndpointOverlay syncs the policy rules for the given endpoint into the shared LPM trie
// and updates the overlay map. Returns the set of offloaded keys.
func SyncEndpointOverlay(epID uint16, entries iter.Seq2[policyTypes.Key, policyTypes.MapStateEntry], ingressPolicyEnabled, egressPolicyEnabled bool) (map[policyTypes.Key]struct{}, error) {
	if !SharedManagerEnabled() {
		return nil, nil
	}

	mgr := getSharedManager()

	var sharedRules []ArenaRuleWithEntry
	offloaded := make(map[policyTypes.Key]struct{})
	seenKeys := make(map[policyTypes.Key]struct{})

	if entries != nil {
		entries(func(key policyTypes.Key, entry policyTypes.MapStateEntry) bool {
			sharedRules = append(sharedRules, ArenaRuleWithEntry{
				Key:   key,
				Entry: entry,
			})
			offloaded[key] = struct{}{}
			seenKeys[key] = struct{}{}
			return true
		})
	}

	// When policy is disabled for a direction, ensure a wildcard allow-all rule exists.
	if !ingressPolicyEnabled {
		wildcardKey := policyTypes.IngressKey()
		if _, ok := seenKeys[wildcardKey]; !ok {
			wildcardEntry := policyTypes.MapStateEntry{}
			sharedRules = append(sharedRules, ArenaRuleWithEntry{
				Key:   wildcardKey,
				Entry: wildcardEntry,
			})
			offloaded[wildcardKey] = struct{}{}
			seenKeys[wildcardKey] = struct{}{}
		}
	}
	if !egressPolicyEnabled {
		wildcardKey := policyTypes.EgressKey()
		if _, ok := seenKeys[wildcardKey]; !ok {
			wildcardEntry := policyTypes.MapStateEntry{}
			sharedRules = append(sharedRules, ArenaRuleWithEntry{
				Key:   wildcardKey,
				Entry: wildcardEntry,
			})
			offloaded[wildcardKey] = struct{}{}
			seenKeys[wildcardKey] = struct{}{}
		}
	}

	// Update rules in allocator (handles refcounting, map updates, and diffing)
	ruleSetID, _, err := mgr.allocator.UpdateEndpointRules(epID, sharedRules)
	if err != nil {
		return nil, fmt.Errorf("failed to update rule set: %w", err)
	}

	// Update overlay map in eBPF
	if err := updateOverlayPolicyEntry(epID, ruleSetID); err != nil {
		return nil, fmt.Errorf("failed to update overlay entry: %w", err)
	}

	return offloaded, nil
}

// RemoveEndpointOverlay deletes the overlay entry and decrements ruleset refcount for the endpoint.
func RemoveEndpointOverlay(epID uint16) {
	if !SharedManagerEnabled() {
		return
	}

	mgr := getSharedManager()

	// Release ruleset reference from allocator
	mgr.allocator.RemoveEndpoint(epID)

	// Delete from BPF overlay map
	_ = deleteOverlayPolicyEntry(epID)
}

// RestoreEndpointOverlay recovers ruleset state during agent restart.
func RestoreEndpointOverlay(epID uint16, ruleSetID uint32) {
	if !SharedManagerEnabled() {
		return
	}

	mgr := getSharedManager()
	if ruleSetID > 0 {
		mgr.allocator.LinkEndpoint(epID, ruleSetID)
	}
}

// RestoreSharedPolicyState recovers the full shared policy state from pinned BPF maps during agent startup.
// It iterates SharedPolicyMap to reconstruct ruleset definitions, links endpoints from PolicyOverlayMap,
// and purges any orphaned rulesets.
func RestoreSharedPolicyState() error {
	if !SharedManagerEnabled() {
		return nil
	}

	mgr := getSharedManager()
	EnsureSharedMapsOpen()

	// 1. Recover rulesets and their rules from SharedPolicyMap
	rulesByRuleSet := make(map[uint32][]SharedRule)
	err := GetSharedPolicyMap().DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key, okK := k.(*SharedPolicyKey)
		val, okV := v.(*PolicyEntry)
		if okK && okV && key.RuleSetID > 0 {
			rulesByRuleSet[key.RuleSetID] = append(rulesByRuleSet[key.RuleSetID], SharedRule{
				Key:   *key,
				Entry: *val,
			})
		}
	})
	if err != nil {
		return fmt.Errorf("failed to dump shared policy map during recovery: %w", err)
	}

	for ruleSetID, rules := range rulesByRuleSet {
		if err := mgr.allocator.RestoreRuleSetWithRules(ruleSetID, rules); err != nil {
			return fmt.Errorf("failed to restore rule set %d: %w", ruleSetID, err)
		}
	}

	// 2. Link endpoints from PolicyOverlayMap
	type overlayMapping struct {
		epID      uint16
		ruleSetID uint32
	}
	var overlayEntries []overlayMapping
	err = GetPolicyOverlayMap().DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
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
			_ = mgr.allocator.RestoreRuleSetWithRules(entry.ruleSetID, nil)
		}
		mgr.allocator.LinkEndpoint(entry.epID, entry.ruleSetID)
	}

	// 3. Clean up any unreferenced/orphaned rule sets from previous crashes or ungraceful terminations
	mgr.allocator.PurgeOrphanedRuleSets()

	return nil
}

func updateOverlayPolicyEntry(epID uint16, ruleSetID uint32) error {
	EnsureSharedMapsOpen()
	key := OverlayKey{EndpointID: uint32(epID)}
	val := OverlayValue{RuleSetID: ruleSetID}
	return GetPolicyOverlayMap().Update(&key, &val)
}

func deleteOverlayPolicyEntry(epID uint16) error {
	EnsureSharedMapsOpen()
	key := OverlayKey{EndpointID: uint32(epID)}
	return GetPolicyOverlayMap().Delete(&key)
}
