// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/cilium/pkg/time"
)

// DefaultGCCacheSize is the default size of the GC cache
const DefaultGCCacheSize = 10000

// GCCache tracks recently garbage-collected FQDN entries.
type GCCache struct {
	cache *lru.Cache[string, time.Time]
	mu    sync.RWMutex
}

// GCCacheEntry represents a garbage-collected FQDN entry.
type GCCacheEntry struct {
	FQDN                  string    `json:"fqdn"`
	GarbageCollectionTime time.Time `json:"garbage-collection-time"`
}

// NewGCCache creates a new GCCache with the specified size.
func NewGCCache(size int) (*GCCache, error) {
	cache, err := lru.New[string, time.Time](size)
	if err != nil {
		return nil, err
	}
	return &GCCache{cache: cache}, nil
}

// Add records that an FQDN was garbage collected.
func (g *GCCache) Add(fqdn string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cache.Add(fqdn, time.Now())
}

// AddMultiple records multiple FQDNs as garbage collected.
func (g *GCCache) AddMultiple(fqdns []string) {
	if len(fqdns) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for _, fqdn := range fqdns {
		g.cache.Add(fqdn, now)
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
