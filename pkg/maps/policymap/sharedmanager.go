// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"fmt"
	"iter"
	"sync"

	"github.com/cilium/ebpf"

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

	var sharedRules []RuleWithEntry
	offloaded := make(map[policyTypes.Key]struct{})
	seenKeys := make(map[policyTypes.Key]struct{})

	if entries != nil {
		entries(func(key policyTypes.Key, entry policyTypes.MapStateEntry) bool {
			sharedRules = append(sharedRules, RuleWithEntry{
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
			sharedRules = append(sharedRules, RuleWithEntry{
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
			sharedRules = append(sharedRules, RuleWithEntry{
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

// DumpEndpointSharedEntries returns the realized shared policy map entries of the rule set
// currently assigned to the given endpoint in the overlay map, converted to the per-endpoint
// PolicyEntriesDump format. Returns nil if the endpoint has no overlay entry.
func DumpEndpointSharedEntries(epID uint16) (PolicyEntriesDump, error) {
	EnsureSharedMapsOpen()

	v, err := GetPolicyOverlayMap().Lookup(&OverlayKey{EndpointID: uint32(epID)})
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

	var entries PolicyEntriesDump
	err = GetSharedPolicyMap().DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key, okK := k.(*SharedPolicyKey)
		val, okV := v.(*PolicyEntry)
		if !okK || !okV || key.RuleSetID != overlay.RuleSetID {
			return
		}
		entries = append(entries, PolicyEntryDump{
			PolicyEntry: *val,
			Key: PolicyKey{
				Prefixlen:        StaticPrefixBits + uint32(key.GetPrefixLen()),
				Identity:         key.Identity,
				TrafficDirection: key.TrafficDirection,
				Nexthdr:          key.Nexthdr,
				DestPortNetwork:  key.DestPortNetwork,
			},
		})
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dump shared policy map: %w", err)
	}
	return entries, nil
}

// HasEndpointOverlay reports whether the endpoint has an overlay entry, i.e. whether the
// datapath enforces the endpoint's policy from the shared policy map. Without an overlay
// entry the datapath uses the endpoint's per-endpoint policy map.
func HasEndpointOverlay(epID uint16) bool {
	if !SharedManagerEnabled() {
		return false
	}
	EnsureSharedMapsOpen()
	_, err := GetPolicyOverlayMap().Lookup(&OverlayKey{EndpointID: uint32(epID)})
	return err == nil
}

// RemoveStaleEndpointOverlays removes the overlay entries and rule set references of
// endpoints for which 'exists' returns false, e.g. endpoints that were deleted while the
// agent was down. This is the shared policy map equivalent of removing the per-endpoint
// policy maps of such endpoints, so that an endpoint reusing the ID never sees the policy
// of the old endpoint.
func RemoveStaleEndpointOverlays(exists func(epID uint16) bool) error {
	if !SharedManagerEnabled() {
		return nil
	}
	EnsureSharedMapsOpen()

	var stale []uint16
	err := GetPolicyOverlayMap().DumpWithCallback(func(k bpf.MapKey, _ bpf.MapValue) {
		if key, ok := k.(*OverlayKey); ok && !exists(uint16(key.EndpointID)) {
			stale = append(stale, uint16(key.EndpointID))
		}
	})
	if err != nil {
		return fmt.Errorf("failed to dump policy overlay map: %w", err)
	}
	for _, epID := range stale {
		RemoveEndpointOverlay(epID)
	}
	return nil
}
