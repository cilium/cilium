// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCIDRTrieMapUpsertDelete(t *testing.T) {
	trieMap := NewCIDRTrieMap[string, string]()

	prefix1 := netip.MustParsePrefix("1.1.1.1/32")
	prefix2 := netip.MustParsePrefix("2.2.2.2/32")
	prefix3 := netip.MustParsePrefix("3.3.3.3/32")
	prefix4 := netip.MustParsePrefix("4.4.4.4/32")

	// new trie map should be empty
	assert.Empty(t, trieMap.m)

	// first upsert is insertion, next one should be an update
	assert.True(t, trieMap.Upsert("key1", prefix1, "prefix"))
	assert.False(t, trieMap.Upsert("key1", prefix1, "prefix1"))

	// same prefix and value in other tries should be insertions, not updates
	assert.True(t, trieMap.Upsert("key2", prefix1, "prefix1"))
	assert.True(t, trieMap.Upsert("key3", prefix1, "prefix1"))

	// further insertions for new prefixes
	assert.True(t, trieMap.Upsert("key1", prefix2, "prefix2"))
	assert.True(t, trieMap.Upsert("key2", prefix3, "prefix3"))
	assert.True(t, trieMap.Upsert("key3", prefix4, "prefix4"))

	// delete prefix2 from "key1" trie, subsequent deletion should fail
	assert.True(t, trieMap.Delete("key1", prefix2))
	assert.False(t, trieMap.Delete("key1", prefix2))

	// prefix3 should not be found in "key1" or "key3" tries
	assert.False(t, trieMap.Delete("key1", prefix3))
	assert.False(t, trieMap.Delete("key3", prefix3))

	// deletion from "non-existent" trie should fail
	assert.False(t, trieMap.Delete("non-existent", prefix1))

	// delete all remaining values from "key1" trie
	assert.True(t, trieMap.Delete("key1", prefix1))

	// "key1" should not be found anymore in the map
	assert.NotContains(t, trieMap.m, "key1")

	// same for "key2" and "key3" trie
	assert.True(t, trieMap.Delete("key2", prefix1))
	assert.True(t, trieMap.Delete("key2", prefix3))
	assert.NotContains(t, trieMap.m, "key2")
	assert.True(t, trieMap.Delete("key3", prefix1))
	assert.True(t, trieMap.Delete("key3", prefix4))
	assert.NotContains(t, trieMap.m, "key3")

	// trie map should be empty
	assert.Empty(t, trieMap.m)
}

func TestCIDRTrieMapDescendants(t *testing.T) {
	trieMap := NewCIDRTrieMap[int, int]()

	prefixes := [][]netip.Prefix{
		{
			netip.MustParsePrefix("192.168.1.1/24"),
			netip.MustParsePrefix("192.168.1.1/28"),
			netip.MustParsePrefix("192.168.1.1/32"),
		},
		{
			netip.MustParsePrefix("192.168.2.1/24"),
			netip.MustParsePrefix("192.168.2.1/28"),
			netip.MustParsePrefix("192.168.2.1/32"),
		},
		{
			netip.MustParsePrefix("192.168.3.1/24"),
			netip.MustParsePrefix("192.168.3.1/28"),
			netip.MustParsePrefix("192.168.3.1/32"),
		},
	}

	for i, keyPrefixes := range prefixes {
		for value, prefix := range keyPrefixes {
			// insert i-th prefix into trie with key "i" and associate "value" to it
			assert.True(t, trieMap.Upsert(i, prefix, value))
		}
	}

	// for each trie, check that the expected descendants (in the correct order) are returned
	for i := range prefixes {
		got := make([]netip.Prefix, len(prefixes[i]))
		trieMap.Descendants(i, prefixes[i][0], func(k netip.Prefix, v int) bool {
			got[v] = k
			return true
		})
		assert.Equal(t, prefixes[i], got)
	}
}
