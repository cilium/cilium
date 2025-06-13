// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logcookie

import (
	"golang.org/x/exp/constraints"

	"github.com/cilium/cilium/pkg/lock"
)

// Bakery allocates unique unsigned integer cookies of type C for a comparable value of type. It
// allows looking up the value for a given cookie and mark-and-sweep garbage collection.
type Bakery[C constraints.Unsigned, V comparable] interface {
	Allocate(value V) (cookie C, ok bool)
	Get(cookie C) (value V, exists bool)
	MarkInUse(cookie C)
	Sweep()
}

type bakery[C constraints.Unsigned, V comparable] struct {
	mu                 lock.RWMutex
	cookieSet          *bitset
	cookieToValue      map[C]holder[V]
	valueToCookie      map[V]C
	lastSeenGeneration uint64
}

var _ Bakery[uint32, string] = (*bakery[uint32, string])(nil)

type holder[T comparable] struct {
	value T
	since uint64
}

// maxOf returns the maximum value for unsigned type T.
func maxOf[T constraints.Unsigned]() T {
	var zero T
	return ^zero
}

// NewBakery creates a new Bakery. It manages cookies of type C for values of type V.
func NewBakery[C constraints.Unsigned, V comparable]() *bakery[C, V] {
	return &bakery[C, V]{
		cookieSet:          newBitset(int(maxOf[C]())),
		cookieToValue:      make(map[C]holder[V]),
		valueToCookie:      make(map[V]C),
		lastSeenGeneration: 0,
	}
}

// Allocate returns a unique, cookie for the given value and whether a cookie could be allocated or
// reused. A successfully allocated cookie is always non-zero. If no cookie could be allocated, a
// zero cookie is returned. If the same value is provided again, Allocate returns the previously
// allocated cookie for that value.
func (b *bakery[C, V]) Allocate(value V) (cookie C, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	cookie, ok = b.valueToCookie[value]
	if ok {
		return cookie, ok
	}
	next, ok := b.cookieSet.Allocate()
	if !ok {
		return 0, false
	}
	// Offset of 1 because a non-zero cookie is needed. Cookie value 0 means no cookie.
	cookie = C(next + 1)
	b.cookieToValue[cookie] = holder[V]{value: value, since: b.lastSeenGeneration}
	b.valueToCookie[value] = cookie
	return cookie, true
}

// Get returns the value for a given cookie and whether it exists in the bakery. If the cookie
// doesn't exist, a zero value will be returned.
func (b *bakery[C, V]) Get(cookie C) (value V, exists bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	v, exists := b.cookieToValue[cookie]
	return v.value, exists
}

// MarkInUse marks a cookie as in-use for the next sweep.
func (b *bakery[C, V]) MarkInUse(cookie C) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if value, ok := b.cookieToValue[cookie]; ok {
		b.cookieToValue[cookie] = holder[V]{
			value: value.value,
			since: b.lastSeenGeneration,
		}
	}
}

// Sweep removes all cookies not marked as in-use since the last time sweep cycle.
func (b *bakery[C, V]) Sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for cookie, val := range b.cookieToValue {
		if val.since < b.lastSeenGeneration {
			delete(b.cookieToValue, cookie)
			delete(b.valueToCookie, val.value)
			b.cookieSet.Release(int(cookie))
		}
	}
	b.lastSeenGeneration++
}
