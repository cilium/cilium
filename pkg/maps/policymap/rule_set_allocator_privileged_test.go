// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
)

func setupRuleSetAllocatorPrivilegedTestSuite(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	logger := hivetest.Logger(tb)
	bpf.CheckOrMountFS(logger, "")

	if err := rlimit.RemoveMemlock(); err != nil {
		tb.Fatal(err)
	}

	// Make sure maps are clean
	_ = os.Remove(bpf.MapPath(logger, SharedPolicyMapName))
	_ = os.Remove(bpf.MapPath(logger, PolicyOverlayMapName))

	// OpenOrCreate maps
	err := SharedPolicyMap.OpenOrCreate()
	require.NoError(tb, err)
}

func TestPrivilegedRuleSetAllocator(t *testing.T) {
	setupRuleSetAllocatorPrivilegedTestSuite(t)
	defer func() {
		SharedPolicyMap.Close()
	}()

	alloc := NewRuleSetAllocator()

	// 1. Prepare some test rules
	rules1 := []ArenaRuleWithEntry{
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

	// 2. Allocate RuleSet ID
	id1, err := alloc.GetOrAllocate(rules1)
	require.NoError(t, err)
	require.Positive(t, id1)

	// 3. Verify they were written to the BPF map
	key1 := NewSharedKey(id1, rules1[0].Key)
	entry1, err := SharedPolicyMap.Lookup(&key1)
	require.NoError(t, err)
	require.NotNil(t, entry1)
	require.Equal(t, uint16(0), entry1.(*PolicyEntry).GetProxyPort())

	key2 := NewSharedKey(id1, rules1[1].Key)
	entry2, err := SharedPolicyMap.Lookup(&key2)
	require.NoError(t, err)
	require.NotNil(t, entry2)
	require.Equal(t, uint16(15001), entry2.(*PolicyEntry).GetProxyPort())

	// 4. Test Deduplication: allocating same rules returns same ID
	id2, err := alloc.GetOrAllocate(rules1)
	require.NoError(t, err)
	require.Equal(t, id1, id2)

	// Release once to bring refcount back to 1 (sole owner)
	released := alloc.ReleaseByID(id1)
	require.False(t, released)

	// Link Endpoint 1 to id1
	alloc.LinkEndpoint(1, id1)

	// 5. Incremental Update: Add a rule (in-place)
	rules2 := append(rules1, ArenaRuleWithEntry{
		Key: policyTypes.KeyForDirection(1).
			WithIdentity(300).
			WithPortProtoPrefix(6, 8080, 16),
		Entry: policyTypes.MapStateEntry{
			ProxyPort:  0,
			Precedence: 0,
		},
	})

	newID, inPlace, err := alloc.UpdateEndpointRules(1, rules2)
	require.NoError(t, err)
	require.True(t, inPlace)
	require.Equal(t, id1, newID)

	// Verify new rule is in the map
	key3 := NewSharedKey(id1, rules2[2].Key)
	entry3, err := SharedPolicyMap.Lookup(&key3)
	require.NoError(t, err)
	require.NotNil(t, entry3)

	// 6. Incremental Update: Remove a rule (in-place)
	rules3 := []ArenaRuleWithEntry{rules2[0], rules2[2]} // Removed rules2[1] (port 443)
	newID, inPlace, err = alloc.UpdateEndpointRules(1, rules3)
	require.NoError(t, err)
	require.True(t, inPlace)
	require.Equal(t, id1, newID)

	// Verify removed rule is gone from BPF map
	_, err = SharedPolicyMap.Lookup(&key2)
	require.Error(t, err)

	// Verify other rules are still there
	_, err = SharedPolicyMap.Lookup(&key1)
	require.NoError(t, err)
	_, err = SharedPolicyMap.Lookup(&key3)
	require.NoError(t, err)

	// 7. Share the ruleset with Endpoint 2
	newID2, inPlace2, err := alloc.UpdateEndpointRules(2, rules3)
	require.NoError(t, err)
	require.False(t, inPlace2) // Ep 2 was not using this ruleset, so it allocates reference
	require.Equal(t, id1, newID2)

	// Now refcount of id1 is 2 (Ep 1 and Ep 2)

	// 8. Update Endpoint 1 (must NOT be in-place, since refcount > 1)
	rules4 := []ArenaRuleWithEntry{rules3[0]} // Ep 1 removes port 8080 rule, leaving only port 80
	newID, inPlace, err = alloc.UpdateEndpointRules(1, rules4)
	require.NoError(t, err)
	require.False(t, inPlace)       // Cannot be in-place!
	require.NotEqual(t, id1, newID) // Must get a new ID!

	// Verify Ep 2's rules are still in map under id1
	_, err = SharedPolicyMap.Lookup(&key3) // port 8080
	require.NoError(t, err)

	// Verify Ep 1's rules are in map under newID
	key1New := NewSharedKey(newID, rules4[0].Key)
	_, err = SharedPolicyMap.Lookup(&key1New)
	require.NoError(t, err)

	// Clean up
	alloc.RemoveEndpoint(1)
	alloc.RemoveEndpoint(2)

	// Both should be deallocated and maps should be empty
	_, err = SharedPolicyMap.Lookup(&key1New)
	require.Error(t, err)
	_, err = SharedPolicyMap.Lookup(&key3)
	require.Error(t, err)
}
