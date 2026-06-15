// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"iter"
	"sync"

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
			allocator: NewRuleSetAllocator(maxRuleSets),
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

	if entries != nil {
		entries(func(key policyTypes.Key, entry policyTypes.MapStateEntry) bool {
			sharedRules = append(sharedRules, ArenaRuleWithEntry{
				Key:   key,
				Entry: entry,
			})
			offloaded[key] = struct{}{}
			return true
		})
	}

	// When policy is disabled for a direction, add a wildcard allow-all rule.
	if !ingressPolicyEnabled {
		wildcardKey := policyTypes.IngressKey()
		wildcardEntry := policyTypes.MapStateEntry{}
		sharedRules = append(sharedRules, ArenaRuleWithEntry{
			Key:   wildcardKey,
			Entry: wildcardEntry,
		})
		offloaded[wildcardKey] = struct{}{}
	}
	if !egressPolicyEnabled {
		wildcardKey := policyTypes.EgressKey()
		wildcardEntry := policyTypes.MapStateEntry{}
		sharedRules = append(sharedRules, ArenaRuleWithEntry{
			Key:   wildcardKey,
			Entry: wildcardEntry,
		})
		offloaded[wildcardKey] = struct{}{}
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
		if err := mgr.allocator.RestoreRuleSet(ruleSetID); err == nil {
			mgr.allocator.LinkEndpoint(epID, ruleSetID)
		}
	}
}

func updateOverlayPolicyEntry(epID uint16, ruleSetID uint32) error {
	EnsureSharedMapsOpen()
	key := OverlayKey{EndpointID: uint32(epID)}
	val := OverlayValue{RuleSetID: ruleSetID}
	return PolicyOverlayMap.Update(&key, &val)
}

func deleteOverlayPolicyEntry(epID uint16) error {
	EnsureSharedMapsOpen()
	key := OverlayKey{EndpointID: uint32(epID)}
	return PolicyOverlayMap.Delete(&key)
}
