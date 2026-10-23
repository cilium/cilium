// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func createTestRules(id uint32, port uint16) []ruleWithEntry {
	return []ruleWithEntry{
		{
			Key: policyTypes.KeyForDirection(trafficdirection.Ingress).
				WithIdentity(identity.NumericIdentity(id)).
				WithPortProto(u8proto.TCP, port),
			Entry: policyTypes.AllowEntry(),
		},
	}
}

func TestRuleSetAllocator_IDRecyclingAndCapacity(t *testing.T) {
	// Create allocator with maxRuleSets = 4 (can allocate IDs 1, 2, 3)
	f := &factory{
		sharedMap:  newFakeBPFMap(),
		overlayMap: newFakeBPFMap(),
		allocator:  NewRuleSetAllocator(WithMaxRuleSets(4)),
	}

	rules1 := createTestRules(100, 80)
	rules2 := createTestRules(200, 80)
	rules3 := createTestRules(300, 80)
	rules4 := createTestRules(400, 80)

	id1, _, err := f.updateEndpointRules(1, rules1)
	require.NoError(t, err)
	require.Equal(t, uint32(1), id1)

	id2, _, err := f.updateEndpointRules(2, rules2)
	require.NoError(t, err)
	require.Equal(t, uint32(2), id2)

	id3, _, err := f.updateEndpointRules(3, rules3)
	require.NoError(t, err)
	require.Equal(t, uint32(3), id3)

	// Allocating beyond capacity must fail
	_, _, err = f.updateEndpointRules(4, rules4)
	require.Error(t, err)
	require.Contains(t, err.Error(), "max rule sets reached")

	// Remove Endpoint 2 -> refcount of ID 2 drops to 0 and ID is recycled
	f.removeEndpointOverlay(2)
	require.NotContains(t, f.allocator.byID, id2)

	// Now allocating rules4 must succeed and recycle the freed ID (2)
	id4, _, err := f.updateEndpointRules(4, rules4)
	require.NoError(t, err)
	require.Equal(t, uint32(2), id4)
}

func TestRuleSetAllocator_EndpointLifecycle(t *testing.T) {
	f, _, _ := setupSharedPolicyFactory()

	rulesA := createTestRules(100, 80)
	rulesB := createTestRules(200, 443)

	// Endpoint 1 uses rulesA
	id1, _, err := f.updateEndpointRules(1, rulesA)
	require.NoError(t, err)
	require.Positive(t, id1)

	// Endpoint 2 also uses rulesA (shared / deduplicated)
	id2, _, err := f.updateEndpointRules(2, rulesA)
	require.NoError(t, err)
	require.Equal(t, id1, id2)
	require.Equal(t, 2, f.allocator.byID[id1].refcount)

	// Endpoint 1 updates to rulesB (new ID allocated, old refcount decremented to 1)
	id1New, inPlace, err := f.updateEndpointRules(1, rulesB)
	require.NoError(t, err)
	require.False(t, inPlace)
	require.NotEqual(t, id1, id1New)
	require.Equal(t, 1, f.allocator.byID[id1].refcount)
	require.Equal(t, 1, f.allocator.byID[id1New].refcount)

	// Remove endpoint 2 -> frees id1 (refcount becomes 0)
	f.removeEndpointOverlay(2)
	require.NotContains(t, f.allocator.byID, id1)

	// Remove endpoint 1 -> frees id1New
	f.removeEndpointOverlay(1)
	require.NotContains(t, f.allocator.byID, id1New)
}

func TestRuleSetAllocator_RestoreRuleSet(t *testing.T) {
	f, _, _ := setupSharedPolicyFactory()

	// Restore ID 5
	f.allocator.restoreRuleSetWithRules(5, nil)

	// Next allocation should start after max restored ID (6)
	rules := createTestRules(100, 80)
	id, _, err := f.updateEndpointRules(1, rules)
	require.NoError(t, err)
	require.Equal(t, uint32(6), id)
}

func TestRuleSetAllocator_HashParity(t *testing.T) {
	testCases := []struct {
		name  string
		rules []ruleWithEntry
	}{
		{
			name:  "empty rules",
			rules: nil,
		},
		{
			name: "single allow rule",
			rules: []ruleWithEntry{
				{
					Key: policyTypes.KeyForDirection(trafficdirection.Ingress).
						WithIdentity(identity.NumericIdentity(100)).
						WithPortProto(u8proto.TCP, 80),
					Entry: policyTypes.AllowEntry(),
				},
			},
		},
		{
			name: "multiple rules with deny, auth, port ranges, and cookies",
			rules: []ruleWithEntry{
				{
					Key: policyTypes.KeyForDirection(trafficdirection.Egress).
						WithIdentity(identity.NumericIdentity(200)).
						WithPortProto(u8proto.UDP, 53),
					Entry: policyTypes.NewMapStateEntry(10, false, 8080, 5),
				},
				{
					Key: policyTypes.KeyForDirection(trafficdirection.Ingress).
						WithIdentity(identity.NumericIdentity(300)).
						WithPortProto(u8proto.TCP, 443),
					Entry: policyTypes.DenyEntry(),
				},
				{
					Key: policyTypes.KeyForDirection(trafficdirection.Ingress).
						WithIdentity(identity.NumericIdentity(400)).
						WithPortProto(u8proto.TCP, 8080),
					Entry: policyTypes.AllowEntry(),
				},
			},
		},
		{
			name: "wildcard rules",
			rules: []ruleWithEntry{
				{
					Key:   policyTypes.IngressKey(),
					Entry: policyTypes.MapStateEntry{},
				},
				{
					Key:   policyTypes.EgressKey(),
					Entry: policyTypes.MapStateEntry{},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hashFromEntries := computeRuleSetHashFromEntries(tc.rules)
			sharedRules := convertToSharedRules(1, tc.rules)
			hashFromShared := computeRuleSetHashFromSharedRules(sharedRules)

			require.Equal(t, hashFromEntries, hashFromShared, "hashes must match between ruleWithEntry and sharedRule")
		})
	}
}

func TestRuleSetAllocator_RestoreSharedPolicyState(t *testing.T) {
	f, fakeShared, fakeOverlay := setupSharedPolicyFactory()

	// Setup initial state:
	// RuleSet 1: Ingress TCP 80, used by Ep 1 and Ep 2
	rules1 := createTestRules(100, 80)
	sharedRules1 := convertToSharedRules(1, rules1)
	for _, r := range sharedRules1 {
		_ = fakeShared.Update(&r.Key, &r.Entry)
	}
	_ = fakeOverlay.Update(&OverlayKey{EndpointID: 1}, &OverlayValue{RuleSetID: 1})
	_ = fakeOverlay.Update(&OverlayKey{EndpointID: 2}, &OverlayValue{RuleSetID: 1})

	// RuleSet 2: Ingress TCP 443, used by Ep 3
	rules2 := createTestRules(200, 443)
	sharedRules2 := convertToSharedRules(2, rules2)
	for _, r := range sharedRules2 {
		_ = fakeShared.Update(&r.Key, &r.Entry)
	}
	_ = fakeOverlay.Update(&OverlayKey{EndpointID: 3}, &OverlayValue{RuleSetID: 2})

	// RuleSet 3: Ingress TCP 8080, orphaned (no endpoint in overlay map)
	rules3 := createTestRules(300, 8080)
	sharedRules3 := convertToSharedRules(3, rules3)
	for _, r := range sharedRules3 {
		_ = fakeShared.Update(&r.Key, &r.Entry)
	}

	// Simulate clean agent restart with the same pinned maps
	f.allocator = NewRuleSetAllocator(WithMaxRuleSets(100))

	// Run recovery
	err := f.restoreSharedPolicyState()
	require.NoError(t, err)

	recAlloc := f.allocator

	// 1. Verify RuleSet 1 and RuleSet 2 are recovered, RuleSet 3 was purged
	require.Equal(t, 2, recAlloc.byID[1].refcount, "RuleSet 1 must have refcount 2")
	require.Equal(t, 1, recAlloc.byID[2].refcount, "RuleSet 2 must have refcount 1")
	require.NotContains(t, recAlloc.byID, uint32(3), "Orphaned RuleSet 3 must be purged")

	// 2. Verify orphaned RuleSet 3 entries were deleted from SharedPolicyMap
	for _, r := range sharedRules3 {
		_, lookupErr := fakeShared.Lookup(&r.Key)
		require.Error(t, lookupErr, "Orphaned RuleSet 3 entries must be deleted from BPF map")
	}

	// 3. Ep 1 regenerates with unchanged rules -> hitless reuse of RuleSet 1
	id, inPlace, err := f.updateEndpointRules(1, rules1)
	require.NoError(t, err)
	require.Equal(t, uint32(1), id, "Ep 1 must reuse RuleSet 1")
	require.False(t, inPlace)
	require.Equal(t, 2, recAlloc.byID[1].refcount)

	// 4. Ep 1 updates to new rules -> allocates new RuleSet (recycles ID 3)
	rulesNew := createTestRules(400, 9090)
	idNew, _, err := f.updateEndpointRules(1, rulesNew)
	require.NoError(t, err)
	require.Equal(t, uint32(3), idNew, "Should recycle purged ID 3")
	require.Equal(t, 1, recAlloc.byID[1].refcount, "RuleSet 1 refcount must decrease to 1")
	require.Equal(t, 1, recAlloc.byID[3].refcount, "RuleSet 3 refcount must be 1")

	// 5. Remove Ep 2 -> RuleSet 1 refcount becomes 0 and is freed from BPF map
	f.removeEndpointOverlay(2)
	require.NotContains(t, recAlloc.byID, uint32(1))
	for _, r := range sharedRules1 {
		_, lookupErr := fakeShared.Lookup(&r.Key)
		require.Error(t, lookupErr, "RuleSet 1 entries must be deleted when last endpoint removed")
	}
}

func TestRuleSetAllocator_IDRecyclingCleansBPFMap(t *testing.T) {
	fakeShared := newFakeBPFMap()
	f := &factory{
		sharedMap:  fakeShared,
		overlayMap: newFakeBPFMap(),
		allocator:  NewRuleSetAllocator(WithMaxRuleSets(4)),
	}

	// 1. Endpoint 1 allocates RuleSet 1 with a wildcard allow rule
	wildcardRules := []ruleWithEntry{
		{
			Key:   policyTypes.IngressKey(),
			Entry: policyTypes.MapStateEntry{},
		},
	}
	id1, _, err := f.updateEndpointRules(1, wildcardRules)
	require.NoError(t, err)
	require.Equal(t, uint32(1), id1)

	// Verify wildcard rule is in BPF map
	sharedWildcard := convertToSharedRules(1, wildcardRules)
	_, err = fakeShared.Lookup(&sharedWildcard[0].Key)
	require.NoError(t, err)

	// 2. Endpoint 1 is removed -> ID 1 is freed
	f.removeEndpointOverlay(1)
	require.NotContains(t, f.allocator.byID, uint32(1))

	// Verify wildcard rule was deleted from BPF map
	_, err = fakeShared.Lookup(&sharedWildcard[0].Key)
	require.Error(t, err)

	// 3. Endpoint 2 allocates a restrictive rule (TCP 80 only) -> recycles ID 1
	restrictiveRules := createTestRules(100, 80)
	id2, _, err := f.updateEndpointRules(2, restrictiveRules)
	require.NoError(t, err)
	require.Equal(t, uint32(1), id2, "Must recycle ID 1")

	// 4. Verify ONLY the restrictive rule is in BPF map, NO leftover wildcard rule!
	sharedRestrictive := convertToSharedRules(1, restrictiveRules)
	_, err = fakeShared.Lookup(&sharedRestrictive[0].Key)
	require.NoError(t, err, "Restrictive rule must exist in BPF map")

	_, err = fakeShared.Lookup(&sharedWildcard[0].Key)
	require.Error(t, err, "Wildcard rule MUST NOT exist in recycled rule set")
}

func TestRuleSetAllocator_RestoreEndpointOverlayLifecycle(t *testing.T) {
	f, fakeShared, fakeOverlay := setupSharedPolicyFactory()

	// 1. Setup existing state: endpoint 10 -> ruleSetID 1
	rules1 := createTestRules(100, 80)
	sharedRules1 := convertToSharedRules(1, rules1)
	for _, r := range sharedRules1 {
		_ = fakeShared.Update(&r.Key, &r.Entry)
	}
	_ = fakeOverlay.Update(&OverlayKey{EndpointID: 10}, &OverlayValue{RuleSetID: 1})

	// Reset allocator to simulate restart
	f.allocator = NewRuleSetAllocator(WithMaxRuleSets(100))

	// 2. Startup recovery
	err := f.restoreSharedPolicyState()
	require.NoError(t, err)

	require.Equal(t, 1, f.allocator.byID[1].refcount, "Refcount after RestoreSharedPolicyState must be 1")

	// 3. Linking a restored endpoint again does not double its reference.
	f.linkEndpoint(10, 1)
	require.Equal(t, 1, f.allocator.byID[1].refcount, "Linking the same endpoint must keep one reference")

	// 4. Endpoint 10 updates policy incrementally (in-place)
	rules1Updated := append(rules1, ruleWithEntry{
		Key: policyTypes.KeyForDirection(trafficdirection.Ingress).
			WithIdentity(identity.NumericIdentity(200)).
			WithPortProto(u8proto.TCP, 8080),
		Entry: policyTypes.MapStateEntry{},
	})
	newID, inPlace, err := f.updateEndpointRules(10, rules1Updated)
	require.NoError(t, err)
	require.Equal(t, uint32(1), newID, "Sole owner must update in-place")
	require.True(t, inPlace)
	require.Equal(t, 1, f.allocator.byID[1].refcount, "Refcount must remain 1")

	// 5. Endpoint 10 is deleted -> RuleSet 1 is completely freed
	f.removeEndpointOverlay(10)
	require.NotContains(t, f.allocator.byID, uint32(1))
}
