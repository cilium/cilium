// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"iter"
)

// InsertOrderedMap is a map that allows iterating over the keys in the order
// they were inserted.
type InsertOrderedMap[K comparable, V any] struct {
	indexes map[K]int
	kvs     []keyValuePair[K, V]
}

type keyValuePair[K, V any] struct {
	key   K
	value V
}

// NewInsertOrderedMap creates a new insert-ordered map.
func NewInsertOrderedMap[K comparable, V any]() *InsertOrderedMap[K, V] {
	return &InsertOrderedMap[K, V]{
		indexes: map[K]int{},
		kvs:     []keyValuePair[K, V]{},
	}
}

// Clear the map.
func (m *InsertOrderedMap[K, V]) Clear() {
	clear(m.indexes)
	m.kvs = m.kvs[:0]
}

// Len returns the number of items in the map.
func (m *InsertOrderedMap[K, V]) Len() int {
	return len(m.kvs)
}

// All returns an iterator for keys and values in the map in insertion order.
func (m *InsertOrderedMap[K, V]) All() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for _, kv := range m.kvs {
			if !yield(kv.key, kv.value) {
				break
			}
		}
	}
}

// Keys returns an iterator for the keys in the map in insertion order.
func (m *InsertOrderedMap[K, V]) Keys() iter.Seq[K] {
	return func(yield func(K) bool) {
		for _, kv := range m.kvs {
			if !yield(kv.key) {
				break
			}
		}
	}
}

// Values returns an iterator for the values in the map in insertion order.
func (m *InsertOrderedMap[K, V]) Values() iter.Seq[V] {
	return func(yield func(V) bool) {
		for _, kv := range m.kvs {
			if !yield(kv.value) {
				break
			}
		}
	}
}

// Get a value from the map. O(1).
func (m *InsertOrderedMap[K, V]) Get(k K) (v V, found bool) {
	var idx int
	idx, found = m.indexes[k]
	if !found {
		return
	}
	return m.kvs[idx].value, true
}

// Delete a key from the map. O(n).
func (m *InsertOrderedMap[K, V]) Delete(k K) (found bool) {
	var idx int
	idx, found = m.indexes[k]
	if !found {
		return
	}
	delete(m.indexes, k)

	// Shift over the deleted element and update indexes
	for i := idx; i < len(m.kvs)-1; i++ {
		m.kvs[i] = m.kvs[i+1]
		m.indexes[m.kvs[i].key] = i
	}
	m.kvs = m.kvs[:len(m.kvs)-1]
	return true
}

// Insert or update a key in the map. O(1).
// An update will not affect the ordering.
func (m *InsertOrderedMap[K, V]) Insert(k K, v V) {
	idx, found := m.indexes[k]
	if found {
		m.kvs[idx].value = v
		return
	}

	idx = len(m.kvs)
	m.indexes[k] = idx
	m.kvs = append(m.kvs, struct {
		key   K
		value V
	}{k, v})
}
