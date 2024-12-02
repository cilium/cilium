// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"sync"
)

const (
	cacheSize = 512
	cacheMask = cacheSize - 1
)

func New[T any](hashfn func(T) uint64, skipfn func(x T) bool, eqfn func(a, b T) bool) *Cache[T] {
	return &Cache[T]{
		hashfn: hashfn,
		eqfn:   eqfn,
		skipfn: skipfn,
		pool: sync.Pool{New: func() any {
			var arr [cacheSize]T
			return &arr
		}},
	}
}

// Cache is a simple fixed size cache for efficient deduplication of objects.
type Cache[T any] struct {
	// pool of cache arrays. Pool is used here as it provides a very efficient
	// shared access to a set of "cache arrays", and under low memory scenarios
	// allows the Go runtime to drop the caches.
	pool sync.Pool

	skipfn func(T) bool
	hashfn func(T) uint64
	eqfn   func(a, b T) bool
}

// Get a cached object if any. If Get() was called previously with an object equal to [x]
// and it is found from the cache then it is returned, otherwise [x] is inserted into
// cache.
func (c *Cache[T]) Get(x T) T {
	if c.skipfn != nil && c.skipfn(x) {
		return x
	}
	x, _ = c.get(x)
	return x
}

func (c *Cache[T]) get(x T) (T, uint64) {
	hash := c.hashfn(x)
	arr := c.pool.Get().(*[cacheSize]T)
	idx := hash & cacheMask
	v := (*arr)[idx]
	if !c.eqfn(x, v) {
		(*arr)[idx] = x
		v = x
	}
	c.pool.Put(arr)
	return v, hash
}
