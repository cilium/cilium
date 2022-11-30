// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package gccache provides an LRU cache to store FQDNs that have been garbage
// collected.

package gccache

import (
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/cilium/api/v1/models"
)

type UninitializedError struct{}

func (ue UninitializedError) Error() string {
	return "FQDN garbage collection cache not yet initialized"
}

// InitGCCache creates a new instance of the FQDN Garbage Collection cache
func InitGCCache(size int) error {
	if size < 1 {
		return fmt.Errorf("failed to initialize FQDN garbage collection cache due to invalid size: %d", size)
	}

	lru, err := lru.New[string, string](size)
	if err != nil {
		return fmt.Errorf("failed to initialize FQDN garbage collection cache: %v", err)
	}
	atomic.StorePointer(&gcCacheLRU, unsafe.Pointer(lru))

	return nil
}

// Add adds new entries to the garbage collection cache
func Add(names ...string) error {
	lru := (*lru.Cache[string, string])(atomic.LoadPointer(&gcCacheLRU))
	if lru == nil {
		return &UninitializedError{}
	}
	time := time.Now().Format(time.RFC3339)
	for _, n := range names {
		lru.Add(n, time)
	}

	return nil
}

// Get retrieves a value from the garbage collection cache and a bool
// indicating whether it is present.
func Get(name string) (string, bool) {
	lru := (*lru.Cache[string, string])(atomic.LoadPointer(&gcCacheLRU))
	if lru == nil {
		return "", false
	}

	return lru.Get(name)
}

// Length returns the size of the garbage collection cache, or -1 if it has not
// yet been initialized.
func Length() int {
	lru := (*lru.Cache[string, string])(atomic.LoadPointer(&gcCacheLRU))
	if lru == nil {
		return 0
	}
	return lru.Len()
}

func Dump() ([]*models.FQDNGCCacheEntry, error) {
	var results []*models.FQDNGCCacheEntry
	lru := (*lru.Cache[string, string])(atomic.LoadPointer(&gcCacheLRU))
	if lru == nil {
		return results, &UninitializedError{}
	}

	for _, key := range lru.Keys() {
		value, ok := lru.Get(key)
		if !ok {
			continue
		}

		results = append(results, &models.FQDNGCCacheEntry{
			Fqdn:                  key,
			GarbageCollectionTime: value,
		})
	}

	return results, nil
}

// gcCacheLRU is the singleton instance of the garbage collection LRU cache
// that's shared throughout Cilium.
var gcCacheLRU unsafe.Pointer
