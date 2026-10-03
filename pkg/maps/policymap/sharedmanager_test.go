// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

// setupSharedManagerTest installs fresh fake shared policy maps and a fresh shared manager,
// as after an agent (re)start, and enables or disables the shared policy map.
func setupSharedManagerTest(t *testing.T, enabled bool) (shared, overlay *FakeBPFMap) {
	t.Helper()

	shared, overlay = NewFakeBPFMap(), NewFakeBPFMap()
	SetSharedPolicyMap(shared)
	SetPolicyOverlayMap(overlay)
	restartSharedManager(enabled)

	old := option.Config.EnableSharedPolicy
	t.Cleanup(func() { option.Config.EnableSharedPolicy = old })
	return shared, overlay
}

// restartSharedManager simulates an agent restart with the shared policy map enabled or
// disabled. The pinned shared policy maps (fakes) are kept as they are.
func restartSharedManager(enabled bool) {
	InitSharedManager(100) // make sure the sync.Once has fired so it can't replace sharedMgr
	sharedMgr = &sharedManager{allocator: NewRuleSetAllocator(WithMaxRuleSets(100))}
	option.Config.EnableSharedPolicy = enabled
}

func entriesOf(rules []RuleWithEntry) func(func(policyTypes.Key, policyTypes.MapStateEntry) bool) {
	return func(yield func(policyTypes.Key, policyTypes.MapStateEntry) bool) {
		for _, r := range rules {
			if !yield(r.Key, r.Entry) {
				return
			}
		}
	}
}

// sharedEntriesFor returns the number of shared policy map entries of the given rule set.
func sharedEntriesFor(t *testing.T, shared *FakeBPFMap, ruleSetID uint32) int {
	t.Helper()
	n := 0
	require.NoError(t, shared.DumpWithCallback(func(k bpf.MapKey, _ bpf.MapValue) {
		if k.(*SharedPolicyKey).RuleSetID == ruleSetID {
			n++
		}
	}))
	return n
}

func overlayRuleSet(t *testing.T, overlay *FakeBPFMap, epID uint16) (uint32, bool) {
	t.Helper()
	v, err := overlay.Lookup(&OverlayKey{EndpointID: uint32(epID)})
	if err != nil {
		return 0, false
	}
	return v.(*OverlayValue).RuleSetID, true
}

func TestHasEndpointOverlay(t *testing.T) {
	_, overlay := setupSharedManagerTest(t, true)

	require.False(t, HasEndpointOverlay(1), "new endpoint has no overlay entry")

	_, err := SyncEndpointOverlay(1, entriesOf(createTestRules(100, 80)), true, true)
	require.NoError(t, err)
	require.True(t, HasEndpointOverlay(1))
	require.False(t, HasEndpointOverlay(2))

	// With the shared policy map disabled, the datapath ignores the overlay map.
	option.Config.EnableSharedPolicy = false
	require.False(t, HasEndpointOverlay(1))
	option.Config.EnableSharedPolicy = true

	RemoveEndpointOverlay(1)
	require.False(t, HasEndpointOverlay(1))
	_, ok := overlayRuleSet(t, overlay, 1)
	require.False(t, ok)
}

func TestRemoveStaleEndpointOverlays(t *testing.T) {
	shared, overlay := setupSharedManagerTest(t, true)

	rulesA := createTestRules(100, 80)
	rulesB := createTestRules(200, 443)
	for epID, rules := range map[uint16][]RuleWithEntry{1: rulesA, 2: rulesB, 3: rulesB} {
		_, err := SyncEndpointOverlay(epID, entriesOf(rules), true, true)
		require.NoError(t, err)
	}
	rsA, _ := overlayRuleSet(t, overlay, 1)
	rsB, _ := overlayRuleSet(t, overlay, 2)
	rsB3, _ := overlayRuleSet(t, overlay, 3)
	require.Equal(t, rsB, rsB3, "endpoints with identical policy share a rule set")

	exists := map[uint16]bool{1: true, 2: true}
	require.NoError(t, RemoveStaleEndpointOverlays(func(id uint16) bool { return exists[id] }))
	require.True(t, HasEndpointOverlay(1))
	require.True(t, HasEndpointOverlay(2))
	require.False(t, HasEndpointOverlay(3), "overlay entry of deleted endpoint removed")
	require.Positive(t, sharedEntriesFor(t, shared, rsB), "rule set still used by endpoint 2")

	delete(exists, 2)
	require.NoError(t, RemoveStaleEndpointOverlays(func(id uint16) bool { return exists[id] }))
	require.False(t, HasEndpointOverlay(2))
	require.Zero(t, sharedEntriesFor(t, shared, rsB), "unused rule set removed from the shared map")
	require.Positive(t, sharedEntriesFor(t, shared, rsA))

	// Disabled: no-op.
	option.Config.EnableSharedPolicy = false
	require.NoError(t, RemoveStaleEndpointOverlays(func(uint16) bool { return false }))
	option.Config.EnableSharedPolicy = true
	require.True(t, HasEndpointOverlay(1))
}

// TestSharedPolicyEnableDisableEnable walks through enabling, disabling and re-enabling the
// shared policy map across agent restarts, from the point of view of the shared policy maps.
//
// When the agent starts with the shared policy map disabled, the map sweeper removes the
// shared policy maps (see mapsweeper.RemoveDisabledMaps), so re-enabling starts from empty
// maps: endpoints have no overlay entry, and the datapath uses their per-endpoint policy maps
// until the agent has realized their current policy in the shared policy map.
func TestSharedPolicyEnableDisableEnable(t *testing.T) {
	shared, overlay := setupSharedManagerTest(t, true)
	rulesOld := createTestRules(100, 80)
	rulesNew := createTestRules(200, 443)

	// 1. Enabled: endpoint 1's policy is realized in the shared map.
	_, err := SyncEndpointOverlay(1, entriesOf(rulesOld), true, true)
	require.NoError(t, err)
	rsOld, ok := overlayRuleSet(t, overlay, 1)
	require.True(t, ok)
	require.Positive(t, sharedEntriesFor(t, shared, rsOld))

	// 2. Agent restarts with the shared policy map disabled. The overlay map is ignored and
	//    the map sweeper removes the shared policy maps. Policy changes while disabled.
	restartSharedManager(false)
	require.False(t, HasEndpointOverlay(1))
	shared, overlay = NewFakeBPFMap(), NewFakeBPFMap() // removed pins, recreated empty
	SetSharedPolicyMap(shared)
	SetPolicyOverlayMap(overlay)

	// 3. Agent restarts with the shared policy map enabled again: nothing to restore.
	restartSharedManager(true)
	require.NoError(t, RestoreSharedPolicyState())
	require.False(t, HasEndpointOverlay(1),
		"no overlay entry: the datapath uses the per-endpoint map until the policy is synced")

	// 4. The endpoint's current policy is synced; the old policy is gone.
	_, err = SyncEndpointOverlay(1, entriesOf(rulesNew), true, true)
	require.NoError(t, err)
	rsNew, ok := overlayRuleSet(t, overlay, 1)
	require.True(t, ok)
	require.Equal(t, len(rulesNew), sharedEntriesFor(t, shared, rsNew))
	n := 0
	require.NoError(t, shared.DumpWithCallback(func(bpf.MapKey, bpf.MapValue) { n++ }))
	require.Equal(t, len(rulesNew), n, "only the current policy is in the shared map")
}

// TestSharedPolicyRestartKeepsState checks that restarting with the shared policy map still
// enabled keeps the realized state, so that the datapath keeps enforcing the endpoint's
// policy across the restart (same as the per-endpoint policy map keeping its entries).
func TestSharedPolicyRestartKeepsState(t *testing.T) {
	shared, overlay := setupSharedManagerTest(t, true)
	rules := createTestRules(100, 80)

	_, err := SyncEndpointOverlay(1, entriesOf(rules), true, true)
	require.NoError(t, err)
	rs, _ := overlayRuleSet(t, overlay, 1)

	restartSharedManager(true)
	require.NoError(t, RestoreSharedPolicyState())
	require.True(t, HasEndpointOverlay(1))
	rsAfter, _ := overlayRuleSet(t, overlay, 1)
	require.Equal(t, rs, rsAfter)
	require.Equal(t, len(rules), sharedEntriesFor(t, shared, rs))

	// Re-syncing the same policy after the restart reuses the rule set (hitless).
	_, err = SyncEndpointOverlay(1, entriesOf(rules), true, true)
	require.NoError(t, err)
	rsAfter, _ = overlayRuleSet(t, overlay, 1)
	require.Equal(t, rs, rsAfter)
}
