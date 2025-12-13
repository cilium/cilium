// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
)

func TestNewGCCache(t *testing.T) {
	cache := NewGCCache(100)
	require.NotNil(t, cache)
	require.Equal(t, 0, cache.Len())

	cache = NewGCCache(1)
	require.NotNil(t, cache)

	require.Panics(t, func() {
		NewGCCache(0)
	})
}

func TestGCCacheAdd(t *testing.T) {
	cache := NewGCCache(100)

	now := time.Now()

	cache.Add([]string{}, now)
	require.Equal(t, 0, cache.Len())

	cache.Add(nil, now)
	require.Equal(t, 0, cache.Len())

	cache.Add([]string{"example.com"}, now)
	require.Equal(t, 1, cache.Len())
	require.True(t, cache.Contains("example.com"))

	cache.Add([]string{"example.com"}, now)
	require.Equal(t, 1, cache.Len())

	cache.Add([]string{"cilium.io", "github.com"}, now)
	require.Equal(t, 3, cache.Len())
	require.True(t, cache.Contains("cilium.io"))
	require.True(t, cache.Contains("github.com"))
}

func TestGCCacheList(t *testing.T) {
	cache := NewGCCache(100)

	entries := cache.List()
	require.Empty(t, entries)

	fqdns := []string{"example.com", "cilium.io", "github.com"}
	now := time.Now()
	cache.Add(fqdns, now)

	entries = cache.List()
	require.Len(t, entries, 3)

	fqdnSet := make(map[string]bool)
	for _, entry := range entries {
		fqdnSet[entry.FQDN] = true
		require.False(t, entry.GarbageCollectionTime.IsZero())
	}
	for _, fqdn := range fqdns {
		require.True(t, fqdnSet[fqdn])
	}
}

func TestGCCacheLRUEviction(t *testing.T) {
	cache := NewGCCache(3)

	now := time.Now()

	cache.Add([]string{"entry1.com", "entry2.com", "entry3.com"}, now)
	require.Equal(t, 3, cache.Len())

	cache.Add([]string{"entry4.com"}, now)
	require.Equal(t, 3, cache.Len())
	require.False(t, cache.Contains("entry1.com"))
	require.True(t, cache.Contains("entry4.com"))

	cache.Add([]string{"entry2.com"}, now)
	cache.Add([]string{"entry5.com"}, now)
	require.Equal(t, 3, cache.Len())
	require.False(t, cache.Contains("entry3.com"))
	require.True(t, cache.Contains("entry2.com"))
	require.True(t, cache.Contains("entry5.com"))
}

func TestGCCacheConcurrentAccess(t *testing.T) {
	cache := NewGCCache(1000)

	var wg sync.WaitGroup
	numGoroutines := 100
	entriesPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < entriesPerGoroutine; j++ {
				fqdn := "entry" + string(rune('a'+id%26)) + ".com"
				cache.Add([]string{fqdn}, time.Now())
			}
		}(i)
	}

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

	require.Positive(t, cache.Len())
	entries := cache.List()
	require.NotEmpty(t, entries)
}
