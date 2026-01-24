// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// DefaultGCCacheSize is the default size of the GC cache
const DefaultGCCacheSize = 10000

// GCCache tracks recently garbage-collected FQDN entries.
type GCCache struct {
	cache *lru.Cache[string, time.Time]
	mu    lock.RWMutex
}

// GCCacheEntry represents a garbage-collected FQDN entry.
type GCCacheEntry struct {
	FQDN                  string    `json:"fqdn"`
	GarbageCollectionTime time.Time `json:"garbage-collection-time"`
}

// NewGCCache creates a new GCCache with the specified size.
func NewGCCache(size int) *GCCache {
	cache, err := lru.New[string, time.Time](size)
	if err != nil {
		panic(err)
	}
	return &GCCache{cache: cache}
}

// Add records FQDNs as garbage collected at the given timestamp.
func (g *GCCache) Add(fqdns []string, ts time.Time) {
	if len(fqdns) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, fqdn := range fqdns {
		g.cache.Add(fqdn, ts)
	}
}

// List returns all entries in the GC cache.
func (g *GCCache) List() []GCCacheEntry {
	g.mu.RLock()
	defer g.mu.RUnlock()

	keys := g.cache.Keys()
	entries := make([]GCCacheEntry, 0, len(keys))
	for _, key := range keys {
		if ts, ok := g.cache.Peek(key); ok {
			entries = append(entries, GCCacheEntry{
				FQDN:                  key,
				GarbageCollectionTime: ts,
			})
		}
	}
	return entries
}

// Len returns the number of entries in the GC cache.
func (g *GCCache) Len() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.cache.Len()
}

// Contains returns true if the FQDN is in the GC cache.
func (g *GCCache) Contains(fqdn string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.cache.Contains(fqdn)
}
