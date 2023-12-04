// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

import "sync"

// Map is a thin generic wrapper around sync.Map. The sync.Map description from
// the standard library follows (and is also propagated to the corresponding
// methods) for users' convenience:
//
// Map is like a Go map[interface{}]interface{} but is safe for concurrent use
// by multiple goroutines without additional locking or coordination.
// Loads, stores, and deletes run in amortized constant time.
//
// The Map type is specialized. Most code should use a plain Go map instead,
// with separate locking or coordination, for better type safety and to make it
// easier to maintain other invariants along with the map content.
//
// The Map type is optimized for two common use cases: (1) when the entry for a given
// key is only ever written once but read many times, as in caches that only grow,
// or (2) when multiple goroutines read, write, and overwrite entries for disjoint
// sets of keys. In these two cases, use of a Map may significantly reduce lock
// contention compared to a Go map paired with a separate Mutex or RWMutex.
//
// The zero Map is empty and ready for use. A Map must not be copied after first use.
type Map[K comparable, V any] sync.Map

// MapCmpValues is an extension of Map, which additionally wraps the two extra
// methods requiring values to be also of comparable type.
type MapCmpValues[K, V comparable] Map[K, V]

// Load returns the value stored in the map for a key, or the zero value if no
// value is present. The ok result indicates whether value was found in the map.
func (m *Map[K, V]) Load(key K) (value V, ok bool) {
	val, ok := (*sync.Map)(m).Load(key)
	return m.convert(val, ok)
}

// LoadOrStore returns the existing value for the key if present.
// Otherwise, it stores and returns the given value.
// The loaded result is true if the value was loaded, false if stored.
func (m *Map[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	val, loaded := (*sync.Map)(m).LoadOrStore(key, value)
	return val.(V), loaded
}

// LoadAndDelete deletes the value for a key, returning the previous value if any
// (zero value otherwise). The loaded result reports whether the key was present.
func (m *Map[K, V]) LoadAndDelete(key K) (value V, loaded bool) {
	val, loaded := (*sync.Map)(m).LoadAndDelete(key)
	return m.convert(val, loaded)
}

// Store sets the value for a key.
func (m *Map[K, V]) Store(key K, value V) {
	(*sync.Map)(m).Store(key, value)
}

// Swap swaps the value for a key and returns the previous value if any (zero
// value otherwise). The loaded result reports whether the key was present.
func (m *Map[K, V]) Swap(key K, value V) (previous V, loaded bool) {
	val, loaded := (*sync.Map)(m).Swap(key, value)
	return m.convert(val, loaded)
}

// Delete deletes the value for a key.
func (m *Map[K, V]) Delete(key K) {
	(*sync.Map)(m).Delete(key)
}

// Range calls f sequentially for each key and value present in the map.
// If f returns false, range stops the iteration.
//
// Range does not necessarily correspond to any consistent snapshot of the Map's
// contents: no key will be visited more than once, but if the value for any key
// is stored or deleted concurrently (including by f), Range may reflect any
// mapping for that key from any point during the Range call. Range does not
// block other methods on the receiver; even f itself may call any method on m.
//
// Range may be O(N) with the number of elements in the map even if f returns
// false after a constant number of calls.
func (m *Map[K, V]) Range(f func(key K, value V) bool) {
	(*sync.Map)(m).Range(func(key, value any) bool {
		return f(key.(K), value.(V))
	})
}

// CompareAndDelete deletes the entry for key if its value is equal to old.
// If there is no current value for key in the map, CompareAndDelete returns false
// (even if the old value is the nil interface value).
func (m *MapCmpValues[K, V]) CompareAndDelete(key K, old V) (deleted bool) {
	return (*sync.Map)(m).CompareAndDelete(key, old)
}

// CompareAndSwap swaps the old and new values for key if the value stored in
// the map is equal to old.
func (m *MapCmpValues[K, V]) CompareAndSwap(key K, old, new V) bool {
	return (*sync.Map)(m).CompareAndSwap(key, old, new)
}

func (m *Map[K, V]) convert(value any, ok bool) (V, bool) {
	if !ok {
		return *new(V), false
	}

	return value.(V), true
}
