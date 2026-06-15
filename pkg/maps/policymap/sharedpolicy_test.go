// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func setupSharedPolicyFactory() (*factory, *fakeBPFMap, *fakeBPFMap) {
	shared, overlay := newFakeBPFMap(), newFakeBPFMap()
	return &factory{
		sharedMap:  shared,
		overlayMap: overlay,
		allocator:  NewRuleSetAllocator(WithMaxRuleSets(100)),
	}, shared, overlay
}

func entriesOf(rules []ruleWithEntry) func(func(policyTypes.Key, policyTypes.MapStateEntry) bool) {
	return func(yield func(policyTypes.Key, policyTypes.MapStateEntry) bool) {
		for _, r := range rules {
			if !yield(r.Key, r.Entry) {
				return
			}
		}
	}
}

// sharedEntriesFor returns the number of shared policy map entries of the given rule set.
func sharedEntriesFor(t *testing.T, shared *fakeBPFMap, ruleSetID uint32) int {
	t.Helper()
	n := 0
	require.NoError(t, shared.DumpWithCallback(func(k bpf.MapKey, _ bpf.MapValue) {
		if k.(*SharedPolicyKey).RuleSetID == ruleSetID {
			n++
		}
	}))
	return n
}

func overlayRuleSet(t *testing.T, overlay *fakeBPFMap, epID uint16) (uint32, bool) {
	t.Helper()
	v, err := overlay.Lookup(&OverlayKey{EndpointID: uint32(epID)})
	if err != nil {
		return 0, false
	}
	return v.(*OverlayValue).RuleSetID, true
}

func TestHasEndpointOverlay(t *testing.T) {
	f, _, overlay := setupSharedPolicyFactory()

	require.False(t, f.HasEndpointOverlay(1), "new endpoint has no overlay entry")

	_, err := f.SyncEndpointOverlay(1, entriesOf(createTestRules(100, 80)), true, true)
	require.NoError(t, err)
	require.True(t, f.HasEndpointOverlay(1))
	require.False(t, f.HasEndpointOverlay(2))

	// Re-syncing unchanged policy repairs a missing overlay entry.
	require.NoError(t, overlay.Delete(&OverlayKey{EndpointID: 1}))
	require.False(t, f.HasEndpointOverlay(1))
	_, err = f.SyncEndpointOverlay(1, entriesOf(createTestRules(100, 80)), true, true)
	require.NoError(t, err)
	require.True(t, f.HasEndpointOverlay(1))

	// With the shared policy map disabled, the datapath ignores the overlay map.
	disabled := &factory{}
	require.False(t, disabled.HasEndpointOverlay(1))

	f.RemoveEndpointOverlay(1)
	require.False(t, f.HasEndpointOverlay(1))
	_, ok := overlayRuleSet(t, overlay, 1)
	require.False(t, ok)
}

func TestRemoveStaleEndpointOverlays(t *testing.T) {
	f, shared, overlay := setupSharedPolicyFactory()

	rulesA := createTestRules(100, 80)
	rulesB := createTestRules(200, 443)
	for epID, rules := range map[uint16][]ruleWithEntry{1: rulesA, 2: rulesB, 3: rulesB} {
		_, err := f.SyncEndpointOverlay(epID, entriesOf(rules), true, true)
		require.NoError(t, err)
	}
	rsA, _ := overlayRuleSet(t, overlay, 1)
	rsB, _ := overlayRuleSet(t, overlay, 2)
	rsB3, _ := overlayRuleSet(t, overlay, 3)
	require.Equal(t, rsB, rsB3, "endpoints with identical policy share a rule set")

	exists := map[uint16]bool{1: true, 2: true}
	require.NoError(t, f.RemoveStaleEndpointOverlays(func(id uint16) bool { return exists[id] }))
	require.True(t, f.HasEndpointOverlay(1))
	require.True(t, f.HasEndpointOverlay(2))
	require.False(t, f.HasEndpointOverlay(3), "overlay entry of deleted endpoint removed")
	require.Positive(t, sharedEntriesFor(t, shared, rsB), "rule set still used by endpoint 2")

	delete(exists, 2)
	require.NoError(t, f.RemoveStaleEndpointOverlays(func(id uint16) bool { return exists[id] }))
	require.False(t, f.HasEndpointOverlay(2))
	require.Zero(t, sharedEntriesFor(t, shared, rsB), "unused rule set removed from the shared map")
	require.Positive(t, sharedEntriesFor(t, shared, rsA))

	// Disabled: no-op.
	disabled := &factory{}
	require.NoError(t, disabled.RemoveStaleEndpointOverlays(func(uint16) bool { return false }))
	require.True(t, f.HasEndpointOverlay(1))
}

// TestSharedPolicyEnableDisableEnable walks through enabling, disabling and re-enabling the
// shared policy map across agent restarts, from the point of view of the shared policy maps.
//
// When the agent starts with the shared policy map disabled, the map sweeper removes the
// shared policy maps (see mapsweeper.RemoveDisabledMaps), so re-enabling starts from empty
// maps: endpoints have no overlay entry, and the datapath uses their per-endpoint policy maps
// until the agent has realized their current policy in the shared policy map.
func TestSharedPolicyEnableDisableEnable(t *testing.T) {
	f, shared, overlay := setupSharedPolicyFactory()
	rulesOld := createTestRules(100, 80)
	rulesNew := createTestRules(200, 443)

	// 1. Enabled: endpoint 1's policy is realized in the shared map.
	_, err := f.SyncEndpointOverlay(1, entriesOf(rulesOld), true, true)
	require.NoError(t, err)
	rsOld, ok := overlayRuleSet(t, overlay, 1)
	require.True(t, ok)
	require.Positive(t, sharedEntriesFor(t, shared, rsOld))

	// 2. Agent restarts with the shared policy map disabled. The overlay map is ignored and
	//    the map sweeper removes the shared policy maps. Policy changes while disabled.
	f = &factory{}
	require.False(t, f.HasEndpointOverlay(1))
	shared, overlay = newFakeBPFMap(), newFakeBPFMap() // removed pins, recreated empty

	// 3. Agent restarts with the shared policy map enabled again: nothing to restore.
	f = &factory{
		sharedMap:  shared,
		overlayMap: overlay,
		allocator:  NewRuleSetAllocator(WithMaxRuleSets(100)),
	}
	require.NoError(t, f.restoreSharedPolicyState())
	require.False(t, f.HasEndpointOverlay(1),
		"no overlay entry: the datapath uses the per-endpoint map until the policy is synced")

	// 4. The endpoint's current policy is synced; the old policy is gone.
	_, err = f.SyncEndpointOverlay(1, entriesOf(rulesNew), true, true)
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
	errDump := errors.New("map dump failed")
	for _, tc := range []struct {
		name       string
		sharedErr  error
		overlayErr error
	}{
		{name: "restore policy"},
		{name: "shared map dump failure", sharedErr: errDump},
		{name: "overlay map dump failure", overlayErr: errDump},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, shared, overlay := setupSharedPolicyFactory()
			rules := createTestRules(100, 80)

			_, err := f.SyncEndpointOverlay(1, entriesOf(rules), true, true)
			require.NoError(t, err)
			rs, _ := overlayRuleSet(t, overlay, 1)

			f = &factory{
				sharedMap:  shared,
				overlayMap: overlay,
				allocator:  NewRuleSetAllocator(WithMaxRuleSets(100)),
			}
			shared.dumpErr = tc.sharedErr
			overlay.dumpErr = tc.overlayErr
			err = f.restoreSharedPolicyState()
			if tc.sharedErr != nil {
				require.ErrorIs(t, err, tc.sharedErr)
				return
			}
			if tc.overlayErr != nil {
				require.ErrorIs(t, err, tc.overlayErr)
				return
			}
			require.NoError(t, err)
			require.True(t, f.HasEndpointOverlay(1))
			rsAfter, _ := overlayRuleSet(t, overlay, 1)
			require.Equal(t, rs, rsAfter)
			require.Equal(t, len(rules), sharedEntriesFor(t, shared, rs))

			// Re-syncing the same policy after the restart reuses the rule set (hitless).
			_, err = f.SyncEndpointOverlay(1, entriesOf(rules), true, true)
			require.NoError(t, err)
			rsAfter, _ = overlayRuleSet(t, overlay, 1)
			require.Equal(t, rs, rsAfter)
		})
	}
}

func TestDumpEndpointSharedEntriesProjection(t *testing.T) {
	f, _, _ := setupSharedPolicyFactory()
	rules := createTestRules(100, 80)

	_, err := f.SyncEndpointOverlay(42, entriesOf(rules), true, true)
	require.NoError(t, err)

	dump, err := f.DumpEndpointSharedEntries(42)
	require.NoError(t, err)
	require.Len(t, dump, len(rules))

	for _, e := range dump {
		require.Equal(t, uint32(100), e.Key.Identity)
		require.Equal(t, uint16(80), e.Key.GetDestPort())
		require.Equal(t, uint8(LPMFullPrefixBits), e.Key.GetPrefixLen())
		require.Equal(t, StatNotAvailable, e.Packets)
		require.Equal(t, StatNotAvailable, e.Bytes)
	}
}

// TestPolicyMapFactoryProvider exercises separate Hives with the same endpoint IDs
// and multiple consumers within each Hive.
func TestPolicyMapFactoryProvider(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
	}{
		{name: "disabled", enabled: false},
		{name: "enabled", enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var first, second Factory
			h := hive.New(
				cell.Provide(
					createFactory,
					func() PolicyConfig { return DefaultPolicyConfig },
					func() *option.DaemonConfig { return &option.DaemonConfig{EnableSharedPolicy: tc.enabled} },
					func() *registry.MapRegistry { return &registry.MapRegistry{} },
				),
				cell.Invoke(func(p Factory) { first = p }),
				cell.Invoke(func(p Factory, _ bpf.MapGroup) { second = p }),
			)
			log := hivetest.Logger(t)
			require.NoError(t, h.Populate(log))
			require.Equal(t, tc.enabled, first.SharedPolicyEnabled())
			if tc.enabled {
				// Populate only: the provider's start hook owns real BPF maps.
				// Supply independent in-memory maps for this API exercise.
				f := first.(*factory)
				f.sharedMap = newFakeBPFMap()
				f.overlayMap = newFakeBPFMap()
			}

			_, err := first.SyncEndpointOverlay(1, entriesOf(createTestRules(100, 80)), true, true)
			require.NoError(t, err)
			require.Equal(t, tc.enabled, second.HasEndpointOverlay(1))
			entries, err := second.DumpEndpointSharedEntries(1)
			require.NoError(t, err)
			if tc.enabled {
				require.Len(t, entries, 1)
			} else {
				require.Empty(t, entries)
			}

			_, err = second.SyncEndpointOverlay(2, entriesOf(createTestRules(200, 443)), true, true)
			require.NoError(t, err)
			second.RemoveEndpointOverlay(1)
			require.False(t, first.HasEndpointOverlay(1))
		})
	}

	t.Run("startup requires ready map registry", func(t *testing.T) {
		h := hive.New(
			cell.Provide(
				createFactory,
				func() PolicyConfig { return DefaultPolicyConfig },
				func() *option.DaemonConfig { return &option.DaemonConfig{EnableSharedPolicy: true} },
				func() *registry.MapRegistry { return &registry.MapRegistry{} },
			),
			cell.Invoke(func(Factory) {}),
		)
		log := hivetest.Logger(t)
		require.ErrorIs(t, h.Start(log, context.Background()), registry.ErrNotStarted)
		require.NoError(t, h.Stop(log, context.Background()))
	})
}
