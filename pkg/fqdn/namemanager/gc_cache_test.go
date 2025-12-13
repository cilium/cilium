// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGCCacheCreation(t *testing.T) {
	// Test valid cache creation
	cache, err := NewGCCache(100)
	require.NoError(t, err)
	require.NotNil(t, cache)
	require.Equal(t, 0, cache.Len())

	// Test cache with size 1
	cache, err = NewGCCache(1)
	require.NoError(t, err)
	require.NotNil(t, cache)

	// Test invalid cache size (0 should fail in lru.New)
	cache, err = NewGCCache(0)
	require.Error(t, err)
	require.Nil(t, cache)
}

func TestGCCacheAdd(t *testing.T) {
	cache, err := NewGCCache(100)
	require.NoError(t, err)

	// Add single entry
	cache.Add("example.com")
	require.Equal(t, 1, cache.Len())
	require.True(t, cache.Contains("example.com"))

	// Add same entry again (should update timestamp)
	cache.Add("example.com")
	require.Equal(t, 1, cache.Len())

	// Add different entry
	cache.Add("cilium.io")
	require.Equal(t, 2, cache.Len())
	require.True(t, cache.Contains("cilium.io"))
}

func TestGCCacheAddMultiple(t *testing.T) {
	cache, err := NewGCCache(100)
	require.NoError(t, err)

	// Add empty slice (should be no-op)
	cache.AddMultiple([]string{})
	require.Equal(t, 0, cache.Len())

	// Add nil slice (should be no-op)
	cache.AddMultiple(nil)
	require.Equal(t, 0, cache.Len())

	// Add multiple entries
	fqdns := []string{"example.com", "cilium.io", "github.com"}
	cache.AddMultiple(fqdns)
	require.Equal(t, 3, cache.Len())
	for _, fqdn := range fqdns {
		require.True(t, cache.Contains(fqdn))
	}
}

func TestGCCacheList(t *testing.T) {
	cache, err := NewGCCache(100)
	require.NoError(t, err)

	// Empty cache should return empty list
	entries := cache.List()
	require.Empty(t, entries)

	// Add some entries and verify list
	fqdns := []string{"example.com", "cilium.io", "github.com"}
	cache.AddMultiple(fqdns)

	entries = cache.List()
	require.Len(t, entries, 3)

	// Verify all FQDNs are present
	fqdnSet := make(map[string]bool)
	for _, entry := range entries {
		fqdnSet[entry.FQDN] = true
		require.False(t, entry.GarbageCollectionTime.IsZero())
	}
	for _, fqdn := range fqdns {
		require.True(t, fqdnSet[fqdn], "expected FQDN %s not found in list", fqdn)
	}
}

func TestGCCacheLRUEviction(t *testing.T) {
	// Create a small cache to test eviction
	cache, err := NewGCCache(3)
	require.NoError(t, err)

	// Fill the cache
	cache.Add("entry1.com")
	cache.Add("entry2.com")
	cache.Add("entry3.com")
	require.Equal(t, 3, cache.Len())

	// Adding a new entry should evict the oldest (entry1.com)
	cache.Add("entry4.com")
	require.Equal(t, 3, cache.Len())
	require.False(t, cache.Contains("entry1.com"), "entry1.com should have been evicted")
	require.True(t, cache.Contains("entry4.com"))

	// Re-add entry2.com to make it recently used
	cache.Add("entry2.com")

	// Add another entry, should evict entry3.com (now the least recently used)
	cache.Add("entry5.com")
	require.Equal(t, 3, cache.Len())
	require.False(t, cache.Contains("entry3.com"), "entry3.com should have been evicted")
	require.True(t, cache.Contains("entry2.com"))
	require.True(t, cache.Contains("entry5.com"))
}

func TestGCCacheConcurrentAccess(t *testing.T) {
	cache, err := NewGCCache(1000)
	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 100
	entriesPerGoroutine := 100

	// Concurrent adds
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < entriesPerGoroutine; j++ {
				fqdn := "entry" + string(rune('a'+id%26)) + ".com"
				cache.Add(fqdn)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < entriesPerGoroutine; j++ {
				_ = cache.List()
				_ = cache.Len()
			}
		}()
	}

	wg.Wait()

	// Cache should still be functional
	require.True(t, cache.Len() > 0)
	entries := cache.List()
	require.NotEmpty(t, entries)
}

func TestGCCacheContains(t *testing.T) {
	cache, err := NewGCCache(100)
	require.NoError(t, err)

	// Empty cache should not contain anything
	require.False(t, cache.Contains("example.com"))

	// Add entry and verify
	cache.Add("example.com")
	require.True(t, cache.Contains("example.com"))
	require.False(t, cache.Contains("other.com"))
}
