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
	"golang.org/x/sys/unix"

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

	err := f.SyncEndpointOverlay(1, entriesOf(createTestRules(100, 80)))
	require.NoError(t, err)
	require.True(t, f.HasEndpointOverlay(1))
	require.False(t, f.HasEndpointOverlay(2))

	// Re-syncing unchanged policy repairs a missing overlay entry.
	require.NoError(t, overlay.Delete(&OverlayKey{EndpointID: 1}))
	require.False(t, f.HasEndpointOverlay(1))
	err = f.SyncEndpointOverlay(1, entriesOf(createTestRules(100, 80)))
	require.NoError(t, err)
	require.True(t, f.HasEndpointOverlay(1))

	// With the shared policy map disabled, the datapath ignores the overlay map.
	disabled := &factory{}
	require.False(t, disabled.HasEndpointOverlay(1))

	f.removeEndpointOverlay(1)
	require.False(t, f.HasEndpointOverlay(1))
	_, ok := overlayRuleSet(t, overlay, 1)
	require.False(t, ok)
}

func TestRemoveStaleEndpointOverlays(t *testing.T) {
	f, shared, overlay := setupSharedPolicyFactory()

	rulesA := createTestRules(100, 80)
	rulesB := createTestRules(200, 443)
	for epID, rules := range map[uint16][]ruleWithEntry{1: rulesA, 2: rulesB, 3: rulesB} {
		err := f.SyncEndpointOverlay(epID, entriesOf(rules))
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
// maps: endpoints have no overlay entry until the agent realizes their current policy in the
// shared policy map, which it does before loading programs that use it. Until then, the
// programs loaded before keep using their per-endpoint policy maps.
func TestSharedPolicyEnableDisableEnable(t *testing.T) {
	f, shared, overlay := setupSharedPolicyFactory()
	rulesOld := createTestRules(100, 80)
	rulesNew := createTestRules(200, 443)

	// 1. Enabled: endpoint 1's policy is realized in the shared map.
	err := f.SyncEndpointOverlay(1, entriesOf(rulesOld))
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
		"no overlay entry until the endpoint's policy is synced before loading its datapath")

	// 4. The endpoint's current policy is synced; the old policy is gone.
	err = f.SyncEndpointOverlay(1, entriesOf(rulesNew))
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

			err := f.SyncEndpointOverlay(1, entriesOf(rules))
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
			err = f.SyncEndpointOverlay(1, entriesOf(rules))
			require.NoError(t, err)
			rsAfter, _ = overlayRuleSet(t, overlay, 1)
			require.Equal(t, rs, rsAfter)
		})
	}
}

// rulesForIdentities returns one ingress TCP/80 allow rule for each of the given identities.
func rulesForIdentities(ids ...uint32) []ruleWithEntry {
	var rules []ruleWithEntry
	for _, id := range ids {
		rules = append(rules, createTestRules(id, 80)...)
	}
	return rules
}

// TestSharedPolicyMapFull checks that a policy update that does not fit in the shared policy
// map fails without changing the rule sets in use, and succeeds once there is space again.
func TestSharedPolicyMapFull(t *testing.T) {
	identitiesOf := func(t *testing.T, f *factory, epID uint16) []uint32 {
		t.Helper()
		dump, err := f.DumpEndpointSharedEntries(epID)
		require.NoError(t, err)
		ids := make([]uint32, 0, len(dump))
		for _, e := range dump {
			ids = append(ids, e.Key.Identity)
		}
		return ids
	}
	totalEntries := func(t *testing.T, shared *fakeBPFMap) int {
		t.Helper()
		n := 0
		require.NoError(t, shared.DumpWithCallback(func(bpf.MapKey, bpf.MapValue) { n++ }))
		return n
	}

	t.Run("in-place update", func(t *testing.T) {
		f, shared, overlay := setupSharedPolicyFactory()
		shared.maxEntries = 3

		require.NoError(t, f.SyncEndpointOverlay(1, entriesOf(rulesForIdentities(100, 101))))
		rs, _ := overlayRuleSet(t, overlay, 1)

		// Adding 102 and 103 before removing 101 needs room for one more entry.
		err := f.SyncEndpointOverlay(1, entriesOf(rulesForIdentities(100, 102, 103)))
		require.ErrorIs(t, err, unix.ENOSPC)
		require.ErrorContains(t, err, PolicySharedMapMaxName)
		rsAfter, _ := overlayRuleSet(t, overlay, 1)
		require.Equal(t, rs, rsAfter, "endpoint keeps its rule set")
		require.ElementsMatch(t, []uint32{100, 101}, identitiesOf(t, f, 1), "rule set is unchanged")
		require.Equal(t, 2, totalEntries(t, shared), "partial changes are reverted")

		// Once there is space again, the update succeeds.
		shared.maxEntries = 0
		require.NoError(t, f.SyncEndpointOverlay(1, entriesOf(rulesForIdentities(100, 102, 103))))
		require.ElementsMatch(t, []uint32{100, 102, 103}, identitiesOf(t, f, 1))
		require.Equal(t, 3, totalEntries(t, shared))
	})

	t.Run("new rule set", func(t *testing.T) {
		f, shared, overlay := setupSharedPolicyFactory()
		shared.maxEntries = 3

		// Endpoints 1 and 2 share a rule set, so a change for endpoint 1 needs a new one.
		for _, epID := range []uint16{1, 2} {
			require.NoError(t, f.SyncEndpointOverlay(epID, entriesOf(rulesForIdentities(100, 101))))
		}
		rs, _ := overlayRuleSet(t, overlay, 1)

		err := f.SyncEndpointOverlay(1, entriesOf(rulesForIdentities(200, 201)))
		require.ErrorIs(t, err, unix.ENOSPC)
		for _, epID := range []uint16{1, 2} {
			rsAfter, _ := overlayRuleSet(t, overlay, epID)
			require.Equal(t, rs, rsAfter, "endpoint keeps its rule set")
			require.ElementsMatch(t, []uint32{100, 101}, identitiesOf(t, f, epID))
		}
		require.Equal(t, 2, totalEntries(t, shared), "partially written rule set is removed")
	})
}

func TestDumpEndpointSharedEntriesProjection(t *testing.T) {
	f, _, _ := setupSharedPolicyFactory()
	rules := createTestRules(100, 80)

	err := f.SyncEndpointOverlay(42, entriesOf(rules))
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

			err := first.SyncEndpointOverlay(1, entriesOf(createTestRules(100, 80)))
			require.NoError(t, err)
			require.Equal(t, tc.enabled, second.HasEndpointOverlay(1))
			entries, err := second.DumpEndpointSharedEntries(1)
			require.NoError(t, err)
			if tc.enabled {
				require.Len(t, entries, 1)
			} else {
				require.Empty(t, entries)
			}

			err = second.SyncEndpointOverlay(2, entriesOf(createTestRules(200, 443)))
			require.NoError(t, err)
			second.(*factory).removeEndpointOverlay(1)
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
