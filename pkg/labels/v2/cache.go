// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"sync"
	"unique"
)

const (
	cacheSize = 256 // Must be power of 2
	cacheMask = cacheSize - 1
)

func newCache[T comparable]() *cache[T] {
	return &cache[T]{
		pool: sync.Pool{New: func() any {
			var xs [cacheSize]unique.Handle[T]
			return &xs
		}},
	}
}

// cache is a sync.Pool-based cache of recently created Label/Labels
// to reduce allocations.
type cache[T comparable] struct {
	pool sync.Pool
}

func (c *cache[T]) lookupOrMake(hash uint64, cmp func(T) bool, new func(hash uint64) T) unique.Handle[T] {
	// zeroHandle has a nil pointer to T inside it that we can compare
	// against.
	var zeroHandle unique.Handle[T]

	arr := c.pool.Get().(*[cacheSize]unique.Handle[T])
	idx := hash & cacheMask
	v := (*arr)[idx]
	if v == zeroHandle || !cmp(v.Value()) {
		v = unique.Make(new(hash))
		(*arr)[idx] = v
	} else {
	}
	c.pool.Put(arr)
	return v
}
