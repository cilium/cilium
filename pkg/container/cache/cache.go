// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"weak"

	"github.com/cilium/cilium/pkg/lock"
)

const (
	cacheSize = 1024
	cacheMask = cacheSize - 1
)

func New[T any](hashfn func(T) uint64, skipfn func(x T) bool, eqfn func(a, b T) bool) *Cache[T] {
	return &Cache[T]{
		hashfn: hashfn,
		eqfn:   eqfn,
		skipfn: skipfn,
	}
}

// Cache is a simple fixed size cache for efficient deduplication of objects.
// The underlying array is held onto with a weak pointer to allow GC to collect
// it when under memory pressure.
type Cache[T any] struct {
	mu  lock.Mutex
	arr weak.Pointer[[cacheSize]T]

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
	x, _ = c.getWithHash(x)
	return x
}

func (c *Cache[T]) getArray() *[cacheSize]T {
	if v := c.arr.Value(); v != nil {
		return v
	}
	arr := [cacheSize]T{}
	c.arr = weak.Make(&arr)
	return &arr
}

func (c *Cache[T]) getWithHash(x T) (T, uint64) {
	hash := c.hashfn(x)
	idx := hash & cacheMask

	c.mu.Lock()
	defer c.mu.Unlock()

	arr := c.getArray()
	v := arr[idx]
	if !c.eqfn(x, v) {
		arr[idx] = x
		v = x
	}
	return v, hash
}

// GetOrPutWith tries to find the object from the cache with the given hash and equality
// function. . If not found, [get] is called to construct the object.
func GetOrPutWith[T any](c *Cache[T], hash uint64, eq func(T) bool, get func() T) T {
	idx := hash & cacheMask

	c.mu.Lock()
	defer c.mu.Unlock()

	arr := c.getArray()
	v := arr[idx]
	if !eq(v) {
		v = get()
		arr[idx] = v
	}
	return v
}
