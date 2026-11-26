// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
)

// countingMap counts the writes to a fakeBPFMap.
type countingMap struct {
	*fakeBPFMap
	updates, deletes int
}

func (m *countingMap) Update(key bpf.MapKey, value bpf.MapValue) error {
	m.updates++
	return m.fakeBPFMap.Update(key, value)
}

func (m *countingMap) Delete(key bpf.MapKey) error {
	m.deletes++
	return m.fakeBPFMap.Delete(key)
}

func (m *countingMap) resetCounts() {
	m.updates, m.deletes = 0, 0
}

// setupCountingFactory returns a factory whose shared and overlay maps count their writes.
func setupCountingFactory(t *testing.T) (*factory, *countingMap, *countingMap) {
	f, _, _ := setupSharedPolicyFactory(t)
	shared := &countingMap{fakeBPFMap: newFakeBPFMap()}
	overlay := &countingMap{fakeBPFMap: newFakeBPFMap()}
	f.sharedMap, f.overlayMap = shared, overlay
	return f, shared, overlay
}

// syncBatch prepares the rules of each endpoint and syncs them together, like the
// endpoints updated by one incremental policy update.
func syncBatch(f *factory, rules map[uint16][]ruleWithEntry) []error {
	var overlays []*EndpointOverlay
	for _, epID := range slices.Sorted(maps.Keys(rules)) {
		overlays = append(overlays, f.PrepareEndpointOverlay(epID, entriesOf(rules[epID])))
	}
	return f.SyncEndpointOverlays(overlays)
}

// sameRules returns a map with the same rules for each endpoint.
func sameRules(rules []ruleWithEntry, epIDs ...uint16) map[uint16][]ruleWithEntry {
	m := make(map[uint16][]ruleWithEntry, len(epIDs))
	for _, epID := range epIDs {
		m[epID] = rules
	}
	return m
}

// TestSyncEndpointOverlaysInPlace checks that when all endpoints that share a rule set get
// the same new rules, the rule set is updated in place: only the changed entries are
// written, and the endpoints keep using the rule set.
func TestSyncEndpointOverlaysInPlace(t *testing.T) {
	f, shared, overlay := setupCountingFactory(t)
	base := rulesForIdentities(100, 101, 102)
	for _, epID := range []uint16{1, 2, 3} {
		require.NoError(t, f.SyncEndpointOverlay(epID, entriesOf(base)))
	}
	rs, _ := overlayRuleSet(t, overlay.fakeBPFMap, 1)
	shared.resetCounts()
	overlay.resetCounts()

	changed := rulesForIdentities(100, 101, 102, 200)
	require.Equal(t, []error{nil, nil, nil}, syncBatch(f, sameRules(changed, 1, 2, 3)))

	require.Equal(t, 1, shared.updates, "only the new entry is written")
	require.Zero(t, shared.deletes)
	require.Zero(t, overlay.updates, "the endpoints keep using the rule set")
	require.Equal(t, 4, totalEntries(t, shared.fakeBPFMap))
	for _, epID := range []uint16{1, 2, 3} {
		id, _ := overlayRuleSet(t, overlay.fakeBPFMap, epID)
		require.Equal(t, rs, id)
		require.ElementsMatch(t, []uint32{100, 101, 102, 200}, endpointIdentities(t, f, epID))
	}

	// Other endpoints find the rule set by its new rules.
	require.NoError(t, f.SyncEndpointOverlay(4, entriesOf(changed)))
	id, _ := overlayRuleSet(t, overlay.fakeBPFMap, 4)
	require.Equal(t, rs, id)
}

// TestSyncEndpointOverlaysDiverging checks that endpoints that share a rule set but get
// different new rules each get their own rules, and that the rule set is not changed in
// place while an endpoint still uses its old rules.
func TestSyncEndpointOverlaysDiverging(t *testing.T) {
	f, _, overlay := setupCountingFactory(t)
	base := rulesForIdentities(100, 101)
	for _, epID := range []uint16{1, 2, 3, 4} {
		require.NoError(t, f.SyncEndpointOverlay(epID, entriesOf(base)))
	}

	// Endpoints 1 and 2 get one change, endpoint 3 another one, and endpoint 4 no change.
	// Endpoint 5 is new.
	a := rulesForIdentities(100, 101, 200)
	b := rulesForIdentities(100, 101, 300)
	errs := syncBatch(f, map[uint16][]ruleWithEntry{1: a, 2: a, 3: b, 5: a})
	require.Equal(t, []error{nil, nil, nil, nil}, errs)

	for _, epID := range []uint16{1, 2, 5} {
		require.ElementsMatch(t, []uint32{100, 101, 200}, endpointIdentities(t, f, epID))
	}
	require.ElementsMatch(t, []uint32{100, 101, 300}, endpointIdentities(t, f, 3))
	require.ElementsMatch(t, []uint32{100, 101}, endpointIdentities(t, f, 4))

	rs1, _ := overlayRuleSet(t, overlay.fakeBPFMap, 1)
	for _, epID := range []uint16{2, 5} {
		id, _ := overlayRuleSet(t, overlay.fakeBPFMap, epID)
		require.Equal(t, rs1, id, "endpoints with the same rules share a rule set")
	}
}

// TestSyncEndpointOverlaysExistingRuleSet checks that endpoints whose new rules are already in
// another rule set switch to it, and that their old rule set is deleted.
func TestSyncEndpointOverlaysExistingRuleSet(t *testing.T) {
	f, shared, overlay := setupCountingFactory(t)
	base := rulesForIdentities(100, 101)
	changed := rulesForIdentities(100, 101, 200)
	require.NoError(t, f.SyncEndpointOverlay(1, entriesOf(base)))
	require.NoError(t, f.SyncEndpointOverlay(2, entriesOf(base)))
	require.NoError(t, f.SyncEndpointOverlay(3, entriesOf(changed)))
	rsOld, _ := overlayRuleSet(t, overlay.fakeBPFMap, 1)
	rs3, _ := overlayRuleSet(t, overlay.fakeBPFMap, 3)
	shared.resetCounts()

	require.Equal(t, []error{nil, nil}, syncBatch(f, sameRules(changed, 1, 2)))

	for _, epID := range []uint16{1, 2} {
		id, _ := overlayRuleSet(t, overlay.fakeBPFMap, epID)
		require.Equal(t, rs3, id)
	}
	require.Zero(t, shared.updates)
	require.Equal(t, 2, shared.deletes, "the old rule set is deleted")
	require.NotContains(t, f.allocator.byID, rsOld)
}

// TestSyncEndpointOverlaysSuperseded checks that a prepared endpoint policy is not synced
// after a later sync, lockdown or removal of the endpoint.
func TestSyncEndpointOverlaysSuperseded(t *testing.T) {
	f, _, overlay := setupCountingFactory(t)
	older := rulesForIdentities(100)
	newer := rulesForIdentities(200)

	// A later sync.
	prepared := f.PrepareEndpointOverlay(1, entriesOf(older))
	require.NoError(t, f.SyncEndpointOverlay(1, entriesOf(newer)))
	require.Equal(t, []error{ErrEndpointOverlaySuperseded}, f.SyncEndpointOverlays([]*EndpointOverlay{prepared}))
	require.ElementsMatch(t, []uint32{200}, endpointIdentities(t, f, 1))

	// A later sync in the same batch, in either order.
	first := f.PrepareEndpointOverlay(1, entriesOf(older))
	second := f.PrepareEndpointOverlay(1, entriesOf(rulesForIdentities(300)))
	require.Equal(t, []error{nil, ErrEndpointOverlaySuperseded}, f.SyncEndpointOverlays([]*EndpointOverlay{second, first}))
	require.ElementsMatch(t, []uint32{300}, endpointIdentities(t, f, 1))
	first = f.PrepareEndpointOverlay(1, entriesOf(older))
	second = f.PrepareEndpointOverlay(1, entriesOf(newer))
	require.Equal(t, []error{ErrEndpointOverlaySuperseded, nil}, f.SyncEndpointOverlays([]*EndpointOverlay{first, second}))
	require.ElementsMatch(t, []uint32{200}, endpointIdentities(t, f, 1))

	// A lockdown.
	prepared = f.PrepareEndpointOverlay(1, entriesOf(older))
	require.NoError(t, f.LockdownEndpoint(1))
	require.Equal(t, []error{ErrEndpointOverlaySuperseded}, f.SyncEndpointOverlays([]*EndpointOverlay{prepared}))
	rs, _ := overlayRuleSet(t, overlay.fakeBPFMap, 1)
	require.Equal(t, uint32(lockdownRuleSetID), rs)

	// A removal.
	prepared = f.PrepareEndpointOverlay(1, entriesOf(older))
	require.NoError(t, f.removeEndpointOverlay(1))
	require.Equal(t, []error{ErrEndpointOverlaySuperseded}, f.SyncEndpointOverlays([]*EndpointOverlay{prepared}))
	require.False(t, f.HasEndpointOverlay(1))
	require.Empty(t, f.allocator.byID, "no rule set is left behind")
}

// TestSyncEndpointOverlaysMapFull checks that when the shared policy map has no room for a
// change to a shared rule set, the endpoints keep their rule set, and that the change is
// applied in place once there is room.
func TestSyncEndpointOverlaysMapFull(t *testing.T) {
	f, shared, overlay := setupCountingFactory(t)
	base := rulesForIdentities(100, 101)
	for _, epID := range []uint16{1, 2} {
		require.NoError(t, f.SyncEndpointOverlay(epID, entriesOf(base)))
	}
	rs, _ := overlayRuleSet(t, overlay.fakeBPFMap, 1)
	shared.maxEntries = 2

	changed := rulesForIdentities(100, 101, 200)
	errs := syncBatch(f, sameRules(changed, 1, 2))
	require.Len(t, errs, 2)
	for _, err := range errs {
		require.ErrorIs(t, err, ErrSharedPolicyMapFull)
	}
	require.Equal(t, 2, totalEntries(t, shared.fakeBPFMap))
	for _, epID := range []uint16{1, 2} {
		id, _ := overlayRuleSet(t, overlay.fakeBPFMap, epID)
		require.Equal(t, rs, id, "the endpoint keeps its rule set")
		require.ElementsMatch(t, []uint32{100, 101}, endpointIdentities(t, f, epID))
	}

	shared.maxEntries = 0
	shared.resetCounts()
	require.Equal(t, []error{nil, nil}, syncBatch(f, sameRules(changed, 1, 2)))
	require.Equal(t, 1, shared.updates)
	for _, epID := range []uint16{1, 2} {
		id, _ := overlayRuleSet(t, overlay.fakeBPFMap, epID)
		require.Equal(t, rs, id)
		require.ElementsMatch(t, []uint32{100, 101, 200}, endpointIdentities(t, f, epID))
	}
}
