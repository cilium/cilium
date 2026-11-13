// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func setupRuleSetAllocatorPrivilegedTestSuite(tb testing.TB) (*factory, *bpf.Map) {
	setupPrivilegedCommon(tb)
	shared, overlay := setupSharedMaps(tb)
	return &factory{
		logger:     hivetest.Logger(tb),
		sharedMap:  shared,
		overlayMap: overlay,
		allocator:  NewRuleSetAllocator(),
	}, shared
}

func TestPrivilegedRuleSetAllocator(t *testing.T) {
	f, sharedMap := setupRuleSetAllocatorPrivilegedTestSuite(t)
	alloc := f.allocator

	// 1. Prepare test rules
	rules1 := []ruleWithEntry{
		{
			Key: policyTypes.KeyForDirection(1).
				WithIdentity(100).
				WithPortProtoPrefix(6, 80, 16),
			Entry: policyTypes.MapStateEntry{
				ProxyPort:  0,
				Precedence: 0,
			},
		},
		{
			Key: policyTypes.KeyForDirection(1).
				WithIdentity(200).
				WithPortProtoPrefix(6, 443, 16),
			Entry: policyTypes.MapStateEntry{
				ProxyPort:  15001,
				Precedence: 0,
			},
		},
	}

	// 2. Allocate RuleSet ID for Endpoint 1
	id1, inPlace, err := f.updateEndpointRules(1, rules1)
	require.NoError(t, err)
	require.Positive(t, id1)
	require.False(t, inPlace)

	// 3. Verify they were written to the BPF map
	key1 := NewSharedKey(id1, rules1[0].Key)
	entry1, err := sharedMap.Lookup(&key1)
	require.NoError(t, err)
	require.NotNil(t, entry1)
	require.Equal(t, uint16(0), entry1.(*PolicyEntry).GetProxyPort())

	key2 := NewSharedKey(id1, rules1[1].Key)
	entry2, err := sharedMap.Lookup(&key2)
	require.NoError(t, err)
	require.NotNil(t, entry2)
	require.Equal(t, uint16(15001), entry2.(*PolicyEntry).GetProxyPort())

	// 4. Test Deduplication: Endpoint 2 allocating same rules gets same ID
	id2, inPlace2, err := f.updateEndpointRules(2, rules1)
	require.NoError(t, err)
	require.Equal(t, id1, id2)
	require.False(t, inPlace2)
	require.Equal(t, 2, alloc.byID[id1].refcount)

	// Release Endpoint 2 -> Endpoint 1 becomes sole owner (refcount 1)
	require.NoError(t, f.removeEndpointOverlay(2))
	require.Equal(t, 1, alloc.byID[id1].refcount)

	// 5. Incremental Update: Add a rule (in-place)
	rules2 := append(rules1, ruleWithEntry{
		Key: policyTypes.KeyForDirection(1).
			WithIdentity(300).
			WithPortProtoPrefix(6, 8080, 16),
		Entry: policyTypes.MapStateEntry{
			ProxyPort:  0,
			Precedence: 0,
		},
	})

	newID, inPlace, err := f.updateEndpointRules(1, rules2)
	require.NoError(t, err)
	require.True(t, inPlace)
	require.Equal(t, id1, newID)

	// Verify new rule is in the map
	key3 := NewSharedKey(id1, rules2[2].Key)
	entry3, err := sharedMap.Lookup(&key3)
	require.NoError(t, err)
	require.NotNil(t, entry3)

	// 6. Incremental Update: Remove a rule (in-place)
	rules3 := []ruleWithEntry{rules2[0], rules2[2]} // Removed rules2[1] (port 443)
	newID, inPlace, err = f.updateEndpointRules(1, rules3)
	require.NoError(t, err)
	require.True(t, inPlace)
	require.Equal(t, id1, newID)

	// Verify removed rule is gone from BPF map
	_, err = sharedMap.Lookup(&key2)
	require.Error(t, err)

	// Verify other rules are still there
	_, err = sharedMap.Lookup(&key1)
	require.NoError(t, err)
	_, err = sharedMap.Lookup(&key3)
	require.NoError(t, err)

	// 7. Share the ruleset with Endpoint 2
	newID2, inPlace2, err := f.updateEndpointRules(2, rules3)
	require.NoError(t, err)
	require.False(t, inPlace2) // Ep 2 was not using this ruleset, so it allocates reference
	require.Equal(t, id1, newID2)

	// Now refcount of id1 is 2 (Ep 1 and Ep 2)

	// 8. Update Endpoint 1 (must NOT be in-place, since refcount > 1)
	rules4 := []ruleWithEntry{rules3[0]} // Ep 1 removes port 8080 rule, leaving only port 80
	newID, inPlace, err = f.updateEndpointRules(1, rules4)
	require.NoError(t, err)
	require.False(t, inPlace)       // Cannot be in-place!
	require.NotEqual(t, id1, newID) // Must get a new ID!

	// Verify Ep 2's rules are still in map under id1
	_, err = sharedMap.Lookup(&key3) // port 8080
	require.NoError(t, err)

	// Verify Ep 1's rules are in map under newID
	key1New := NewSharedKey(newID, rules4[0].Key)
	_, err = sharedMap.Lookup(&key1New)
	require.NoError(t, err)

	// 9. Verify cilium-dbg legacy projection (OpenPolicyMap + DumpToSlice + OpenOverlayEndpointIDs)
	logger := hivetest.Logger(t)
	statsMap, err := createStatsMapForTest(testMapSize)
	require.NoError(t, err)
	defer statsMap.Close()

	epIDs, err := OpenOverlayEndpointIDs(bpf.MapPath(logger, PolicyOverlayMapName))
	require.NoError(t, err)
	require.Equal(t, []uint16{1, 2}, epIDs)

	pm1, err := OpenPolicyMap(logger, bpf.LocalMapPath(logger, MapName, 1))
	require.NoError(t, err)
	defer pm1.Close()
	dump1, err := pm1.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump1, len(rules4))
	require.Equal(t, uint16(80), dump1[0].Key.GetDestPort())

	// Clean up
	require.NoError(t, f.removeEndpointOverlay(1))
	require.NoError(t, f.removeEndpointOverlay(2))

	// Both should be deallocated and maps should be empty
	_, err = sharedMap.Lookup(&key1New)
	require.Error(t, err)
	_, err = sharedMap.Lookup(&key3)
	require.Error(t, err)
}

// TestPrivilegedSharedPolicyLockdown checks with BPF maps that a policy update that does not
// fit in the shared policy map fails with ErrSharedPolicyMapFull, and that locking an endpoint
// down points it to lockdownRuleSetID and deletes its rule set.
func TestPrivilegedSharedPolicyLockdown(t *testing.T) {
	setupPrivilegedCommon(t)
	shared := bpf.NewMap(SharedPolicyMapName, ebpf.LPMTrie, &SharedPolicyKey{}, &PolicyEntry{},
		3, unix.BPF_F_NO_PREALLOC)
	require.NoError(t, shared.CreateUnpinned())
	t.Cleanup(func() { shared.Close() })
	overlay := bpf.NewMap(PolicyOverlayMapName, ebpf.Hash, &OverlayKey{}, &OverlayValue{},
		16, unix.BPF_F_NO_PREALLOC)
	require.NoError(t, overlay.CreateUnpinned())
	t.Cleanup(func() { overlay.Close() })
	f := &factory{
		logger:     hivetest.Logger(t),
		sharedMap:  shared,
		overlayMap: overlay,
		allocator:  NewRuleSetAllocator(),
	}

	require.NoError(t, f.SyncEndpointOverlay(1, entriesOf(rulesForIdentities(100, 101))))

	// Endpoint 2 needs two entries, but there is room for one.
	err := f.SyncEndpointOverlay(2, entriesOf(rulesForIdentities(200, 201)))
	require.ErrorIs(t, err, ErrSharedPolicyMapFull)
	require.ErrorIs(t, err, unix.ENOSPC)

	require.NoError(t, f.LockdownEndpoint(1))
	v, err := overlay.Lookup(&OverlayKey{EndpointID: 1})
	require.NoError(t, err)
	require.Equal(t, uint32(lockdownRuleSetID), v.(*OverlayValue).RuleSetID)
	require.Empty(t, endpointIdentities(t, f, 1))

	// The space freed by endpoint 1 is used by endpoint 2.
	require.NoError(t, f.SyncEndpointOverlay(2, entriesOf(rulesForIdentities(200, 201))))
	require.ElementsMatch(t, []uint32{200, 201}, endpointIdentities(t, f, 2))
}
