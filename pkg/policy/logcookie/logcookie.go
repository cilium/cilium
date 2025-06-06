// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logcookie

import (
	"math"

	"github.com/cilium/cilium/pkg/lock"
)

// Bakery allocates unique uint32 cookies for lists of strings,
// allows reverse lookup, and supports mark-and-sweep.
type Backery[T comparable] interface {
	Allocate(entry T) (uint32, bool)
	Get(cookie uint32) (T, bool)
	MarkInUse(cookie uint32)
	Sweep(numRevisions uint64)
}

type bakery[T comparable] struct {
	mu            lock.RWMutex
	cookieSet     *bitset
	cookieToValue map[uint32]holder[T]
	valueToCookie map[T]uint32
	revision      uint64
}

var _ Backery[string] = (*bakery[string])(nil)

type holder[T comparable] struct {
	value T
	since uint64
}

// NewBakery creates a new Bakery.
func NewBakery[T comparable]() *bakery[T] {
	return &bakery[T]{
		cookieSet:     newBitset(math.MaxUint32),
		cookieToValue: make(map[uint32]holder[T]),
		valueToCookie: make(map[T]uint32),
		revision:      0,
	}
}

// Allocate returns a unique cookie for the given value. If no cookie could be allocated,
// If the same value is provided again, it returns the same cookie.
func (b *bakery[T]) Allocate(value T) (uint32, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	cookie, ok := b.valueToCookie[value]
	if ok {
		return cookie, ok
	}
	next, ok := b.cookieSet.Allocate()
	if !ok {
		return 0, false
	}
	cookie = uint32(next)
	b.cookieToValue[cookie] = holder[T]{value: value, since: b.revision}
	b.valueToCookie[value] = cookie
	return cookie, true
}

// Get returns the value for a given cookie if present, and whether it was found.
func (b *bakery[T]) Get(cookie uint32) (T, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	value, ok := b.cookieToValue[cookie]
	return value.value, ok
}

// MarkInUse marks a cookie as in-use for the next sweep.
func (b *bakery[T]) MarkInUse(cookie uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if value, ok := b.cookieToValue[cookie]; ok {
		b.cookieToValue[cookie] = holder[T]{
			value: value.value,
			since: b.revision,
		}
	}
}

// Sweep removes all cookies not marked as in-use since numRevisions revisions.
func (b *bakery[T]) Sweep(numRevisions uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for cookie, val := range b.cookieToValue {
		if val.since+numRevisions < b.revision {
			delete(b.cookieToValue, cookie)
			delete(b.valueToCookie, val.value)
			b.cookieSet.Release(int(cookie))
		}
	}
}
