// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func createTestRules(id uint32, port uint16) []ArenaRuleWithEntry {
	return []ArenaRuleWithEntry{
		{
			Key: policyTypes.KeyForDirection(trafficdirection.Ingress).
				WithIdentity(identity.NumericIdentity(id)).
				WithPortProto(u8proto.TCP, port),
			Entry: policyTypes.AllowEntry(),
		},
	}
}

func TestRuleSetAllocator_BasicAndDedup(t *testing.T) {
	SetSharedPolicyMap(NewFakeBPFMap())
	SetPolicyOverlayMap(NewFakeBPFMap())

	alloc := NewRuleSetAllocator()

	rulesA := createTestRules(100, 80)
	rulesB := createTestRules(200, 443)

	// 1. Allocate rulesA
	id1, err := alloc.GetOrAllocate(rulesA)
	require.NoError(t, err)
	require.Positive(t, id1)

	// 2. Allocate identical rulesA -> same ID (deduplication)
	id2, err := alloc.GetOrAllocate(rulesA)
	require.NoError(t, err)
	require.Equal(t, id1, id2)

	// 3. Allocate rulesB -> distinct ID
	id3, err := alloc.GetOrAllocate(rulesB)
	require.NoError(t, err)
	require.NotEqual(t, id1, id3)

	// 4. Release id1 once -> not freed (refcount 2 -> 1)
	freed := alloc.ReleaseByID(id1)
	require.False(t, freed)

	// 5. Release id1 second time -> freed (refcount 1 -> 0)
	freed = alloc.ReleaseByID(id1)
	require.True(t, freed)
}

func TestRuleSetAllocator_IDRecyclingAndCapacity(t *testing.T) {
	SetSharedPolicyMap(NewFakeBPFMap())
	SetPolicyOverlayMap(NewFakeBPFMap())

	// Create allocator with maxRuleSets = 4 (can allocate IDs 1, 2, 3)
	alloc := NewRuleSetAllocator(WithMaxRuleSets(4))

	rules1 := createTestRules(100, 80)
	rules2 := createTestRules(200, 80)
	rules3 := createTestRules(300, 80)
	rules4 := createTestRules(400, 80)

	id1, err := alloc.GetOrAllocate(rules1)
	require.NoError(t, err)
	require.Equal(t, uint32(1), id1)

	id2, err := alloc.GetOrAllocate(rules2)
	require.NoError(t, err)
	require.Equal(t, uint32(2), id2)

	id3, err := alloc.GetOrAllocate(rules3)
	require.NoError(t, err)
	require.Equal(t, uint32(3), id3)

	// Allocating beyond capacity must fail
	_, err = alloc.GetOrAllocate(rules4)
	require.Error(t, err)
	require.Contains(t, err.Error(), "max rule sets reached")

	// Release ID 2 -> refcount drops to 0 and ID is recycled
	freed := alloc.ReleaseByID(id2)
	require.True(t, freed)

	// Now allocating rules4 must succeed and recycle the freed ID (2)
	id4, err := alloc.GetOrAllocate(rules4)
	require.NoError(t, err)
	require.Equal(t, uint32(2), id4)
}

func TestRuleSetAllocator_EndpointLifecycle(t *testing.T) {
	SetSharedPolicyMap(NewFakeBPFMap())
	SetPolicyOverlayMap(NewFakeBPFMap())

	alloc := NewRuleSetAllocator()

	rulesA := createTestRules(100, 80)
	rulesB := createTestRules(200, 443)

	// Endpoint 1 uses rulesA
	id1, _, err := alloc.UpdateEndpointRules(1, rulesA)
	require.NoError(t, err)

	// Endpoint 2 also uses rulesA (shared)
	id2, _, err := alloc.UpdateEndpointRules(2, rulesA)
	require.NoError(t, err)
	require.Equal(t, id1, id2)

	// Endpoint 1 updates to rulesB (new ID allocated, old refcount decremented)
	id1New, inPlace, err := alloc.UpdateEndpointRules(1, rulesB)
	require.NoError(t, err)
	require.False(t, inPlace)
	require.NotEqual(t, id1, id1New)

	// Remove endpoint 2 -> frees id1 (refcount becomes 0)
	alloc.RemoveEndpoint(2)

	// Remove endpoint 1 -> frees id1New
	alloc.RemoveEndpoint(1)
}

func TestRuleSetAllocator_RestoreRuleSet(t *testing.T) {
	SetSharedPolicyMap(NewFakeBPFMap())
	SetPolicyOverlayMap(NewFakeBPFMap())

	alloc := NewRuleSetAllocator(WithMaxRuleSets(100))

	// Restore ID 5
	err := alloc.RestoreRuleSet(5)
	require.NoError(t, err)

	// Next allocation should start after max restored ID (6)
	rules := createTestRules(100, 80)
	id, err := alloc.GetOrAllocate(rules)
	require.NoError(t, err)
	require.Equal(t, uint32(6), id)
}

func TestRuleSetAllocator_HashParity(t *testing.T) {
	alloc := NewRuleSetAllocator()

	testCases := []struct {
		name  string
		rules []ArenaRuleWithEntry
	}{
		{
			name:  "empty rules",
			rules: nil,
		},
		{
			name: "single allow rule",
			rules: []ArenaRuleWithEntry{
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
			rules: []ArenaRuleWithEntry{
				{
					Key: policyTypes.KeyForDirection(trafficdirection.Egress).
						WithIdentity(identity.NumericIdentity(200)).
						WithPortProto(u8proto.UDP, 53),
					Entry: policyTypes.NewMapStateEntry(10, false, 8080, 5, policyTypes.NoAuthRequirement),
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
			rules: []ArenaRuleWithEntry{
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
			hashFromEntries := ComputeRuleSetHashFromEntries(tc.rules)
			sharedRules := alloc.convertToSharedRules(1, tc.rules)
			hashFromShared := ComputeRuleSetHashFromSharedRules(sharedRules)

			require.Equal(t, hashFromEntries, hashFromShared, "hashes must match between ArenaRuleWithEntry and SharedRule")
		})
	}
}

func TestRuleSetAllocator_RestoreSharedPolicyState(t *testing.T) {
	fakeShared := NewFakeBPFMap()
	fakeOverlay := NewFakeBPFMap()
	SetSharedPolicyMap(fakeShared)
	SetPolicyOverlayMap(fakeOverlay)

	option.Config.EnableSharedPolicy = true
	defer func() { option.Config.EnableSharedPolicy = false }()

	alloc := NewRuleSetAllocator(WithMaxRuleSets(100))

	// Setup initial state:
	// RuleSet 1: Ingress TCP 80, used by Ep 1 and Ep 2
	rules1 := createTestRules(100, 80)
	sharedRules1 := alloc.convertToSharedRules(1, rules1)
	for _, r := range sharedRules1 {
		_ = fakeShared.Update(&r.Key, &r.Entry)
	}
	_ = fakeOverlay.Update(&OverlayKey{EndpointID: 1}, &OverlayValue{RuleSetID: 1})
	_ = fakeOverlay.Update(&OverlayKey{EndpointID: 2}, &OverlayValue{RuleSetID: 1})

	// RuleSet 2: Ingress TCP 443, used by Ep 3
	rules2 := createTestRules(200, 443)
	sharedRules2 := alloc.convertToSharedRules(2, rules2)
	for _, r := range sharedRules2 {
		_ = fakeShared.Update(&r.Key, &r.Entry)
	}
	_ = fakeOverlay.Update(&OverlayKey{EndpointID: 3}, &OverlayValue{RuleSetID: 2})

	// RuleSet 3: Ingress TCP 8080, orphaned (no endpoint in overlay map)
	rules3 := createTestRules(300, 8080)
	sharedRules3 := alloc.convertToSharedRules(3, rules3)
	for _, r := range sharedRules3 {
		_ = fakeShared.Update(&r.Key, &r.Entry)
	}

	// Reset shared manager to simulate clean agent restart
	sharedMgr = &sharedManager{
		allocator: NewRuleSetAllocator(WithMaxRuleSets(100)),
	}

	// Run recovery
	err := RestoreSharedPolicyState()
	require.NoError(t, err)

	recMgr := getSharedManager()
	recAlloc := recMgr.allocator

	// 1. Verify RuleSet 1 and RuleSet 2 are recovered, RuleSet 3 was purged
	require.Equal(t, 2, recAlloc.refcount[1], "RuleSet 1 must have refcount 2")
	require.Equal(t, 1, recAlloc.refcount[2], "RuleSet 2 must have refcount 1")
	require.NotContains(t, recAlloc.refcount, uint32(3), "Orphaned RuleSet 3 must be purged")

	// 2. Verify orphaned RuleSet 3 entries were deleted from SharedPolicyMap
	for _, r := range sharedRules3 {
		_, lookupErr := fakeShared.Lookup(&r.Key)
		require.Error(t, lookupErr, "Orphaned RuleSet 3 entries must be deleted from BPF map")
	}

	// 3. Ep 1 regenerates with unchanged rules -> hitless reuse of RuleSet 1
	id, inPlace, err := recAlloc.UpdateEndpointRules(1, rules1)
	require.NoError(t, err)
	require.Equal(t, uint32(1), id, "Ep 1 must reuse RuleSet 1")
	require.False(t, inPlace)
	require.Equal(t, 2, recAlloc.refcount[1])

	// 4. Ep 1 updates to new rules -> allocates new RuleSet (recycles ID 3)
	rulesNew := createTestRules(400, 9090)
	idNew, _, err := recAlloc.UpdateEndpointRules(1, rulesNew)
	require.NoError(t, err)
	require.Equal(t, uint32(3), idNew, "Should recycle purged ID 3")
	require.Equal(t, 1, recAlloc.refcount[1], "RuleSet 1 refcount must decrease to 1")
	require.Equal(t, 1, recAlloc.refcount[3], "RuleSet 3 refcount must be 1")

	// 5. Remove Ep 2 -> RuleSet 1 refcount becomes 0 and is freed from BPF map
	recAlloc.RemoveEndpoint(2)
	require.NotContains(t, recAlloc.refcount, uint32(1))
	for _, r := range sharedRules1 {
		_, lookupErr := fakeShared.Lookup(&r.Key)
		require.Error(t, lookupErr, "RuleSet 1 entries must be deleted when last endpoint removed")
	}
}

func TestRuleSetAllocator_IDRecyclingCleansBPFMap(t *testing.T) {
	fakeShared := NewFakeBPFMap()
	fakeOverlay := NewFakeBPFMap()
	SetSharedPolicyMap(fakeShared)
	SetPolicyOverlayMap(fakeOverlay)

	alloc := NewRuleSetAllocator(WithMaxRuleSets(4))

	// 1. Endpoint 1 allocates RuleSet 1 with a wildcard allow rule
	wildcardRules := []ArenaRuleWithEntry{
		{
			Key:   policyTypes.IngressKey(),
			Entry: policyTypes.MapStateEntry{},
		},
	}
	id1, _, err := alloc.UpdateEndpointRules(1, wildcardRules)
	require.NoError(t, err)
	require.Equal(t, uint32(1), id1)

	// Verify wildcard rule is in BPF map
	sharedWildcard := alloc.convertToSharedRules(1, wildcardRules)
	_, err = fakeShared.Lookup(&sharedWildcard[0].Key)
	require.NoError(t, err)

	// 2. Endpoint 1 is removed -> ID 1 is freed
	alloc.RemoveEndpoint(1)
	require.NotContains(t, alloc.refcount, uint32(1))

	// Verify wildcard rule was deleted from BPF map
	_, err = fakeShared.Lookup(&sharedWildcard[0].Key)
	require.Error(t, err)

	// 3. Endpoint 2 allocates a restrictive rule (TCP 80 only) -> recycles ID 1
	restrictiveRules := createTestRules(100, 80)
	id2, _, err := alloc.UpdateEndpointRules(2, restrictiveRules)
	require.NoError(t, err)
	require.Equal(t, uint32(1), id2, "Must recycle ID 1")

	// 4. Verify ONLY the restrictive rule is in BPF map, NO leftover wildcard rule!
	sharedRestrictive := alloc.convertToSharedRules(1, restrictiveRules)
	_, err = fakeShared.Lookup(&sharedRestrictive[0].Key)
	require.NoError(t, err, "Restrictive rule must exist in BPF map")

	_, err = fakeShared.Lookup(&sharedWildcard[0].Key)
	require.Error(t, err, "Wildcard rule MUST NOT exist in recycled rule set")
}

func TestRuleSetAllocator_RestoreEndpointOverlayLifecycle(t *testing.T) {
	fakeShared := NewFakeBPFMap()
	fakeOverlay := NewFakeBPFMap()
	SetSharedPolicyMap(fakeShared)
	SetPolicyOverlayMap(fakeOverlay)

	option.Config.EnableSharedPolicy = true
	defer func() { option.Config.EnableSharedPolicy = false }()

	// 1. Setup existing state: endpoint 10 -> ruleSetID 1
	rules1 := createTestRules(100, 80)
	alloc := NewRuleSetAllocator()
	sharedRules1 := alloc.convertToSharedRules(1, rules1)
	for _, r := range sharedRules1 {
		_ = fakeShared.Update(&r.Key, &r.Entry)
	}
	_ = fakeOverlay.Update(&OverlayKey{EndpointID: 10}, &OverlayValue{RuleSetID: 1})

	// Reset manager to simulate restart
	sharedMgr = &sharedManager{
		allocator: NewRuleSetAllocator(WithMaxRuleSets(100)),
	}

	// 2. Startup recovery
	err := RestoreSharedPolicyState()
	require.NoError(t, err)

	recMgr := getSharedManager()
	require.Equal(t, 1, recMgr.allocator.refcount[1], "Refcount after RestoreSharedPolicyState must be 1")

	// 3. Endpoint restoration calls RestoreEndpointOverlay(10, 1)
	RestoreEndpointOverlay(10, 1)
	require.Equal(t, 1, recMgr.allocator.refcount[1], "Refcount after RestoreEndpointOverlay must remain 1 (no double increment)")

	// 4. Endpoint 10 updates policy incrementally (in-place)
	rules1Updated := append(rules1, ArenaRuleWithEntry{
		Key: policyTypes.KeyForDirection(trafficdirection.Ingress).
			WithIdentity(identity.NumericIdentity(200)).
			WithPortProto(u8proto.TCP, 8080),
		Entry: policyTypes.MapStateEntry{},
	})
	newID, inPlace, err := recMgr.allocator.UpdateEndpointRules(10, rules1Updated)
	require.NoError(t, err)
	require.Equal(t, uint32(1), newID, "Sole owner must update in-place")
	require.True(t, inPlace)
	require.Equal(t, 1, recMgr.allocator.refcount[1], "Refcount must remain 1")

	// 5. Endpoint 10 is deleted -> RuleSet 1 is completely freed
	recMgr.allocator.RemoveEndpoint(10)
	require.NotContains(t, recMgr.allocator.refcount, uint32(1))
}
