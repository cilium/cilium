// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import "encoding/binary"

func NewStringMap[V any]() Map[string, V] {
	return NewMap[string, V](
		func(s string) []byte { return []byte(s) },
		func(b []byte) string { return string(b) },
	)
}

func NewBytesMap[V any]() Map[[]byte, V] {
	identity := func(b []byte) []byte { return b }
	return NewMap[[]byte, V](
		identity,
		identity,
	)
}

func NewUint64Map[V any]() Map[uint64, V] {
	return NewMap[uint64, V](
		func(x uint64) []byte {
			return binary.BigEndian.AppendUint64(nil, x)
		},
		binary.BigEndian.Uint64,
	)
}

// NewMap creates a new persistent map. The toBytes function maps the key
// into bytes, and fromBytes does the reverse.
func NewMap[K, V any](toBytes func(K) []byte, fromBytes func([]byte) K) Map[K, V] {
	return Map[K, V]{
		toBytes:   toBytes,
		fromBytes: fromBytes,
		tree:      nil,
	}
}

// MapIterator iterates over key and value pairs.
type MapIterator[K, V any] struct {
	fromBytes func([]byte) K
	iter      *Iterator[V]
}

// Next returns the next key and value. If the iterator
// is exhausted it returns false.
func (it MapIterator[K, V]) Next() (k K, v V, ok bool) {
	if it.iter == nil {
		return
	}
	var b []byte
	b, v, ok = it.iter.Next()
	if ok {
		k = it.fromBytes(b)
	}
	return
}

// FromMap copies values from the hash map into the given Map.
// This is not implemented as a method on Map[K,V] as hash maps require the
// comparable constraint and we do not need to limit Map[K, V] to that.
func FromMap[K comparable, V any](m Map[K, V], hm map[K]V) Map[K, V] {
	m.ensureTree()
	txn := m.tree.Txn()
	for k, v := range hm {
		txn.Insert(m.toBytes(k), v)
	}
	m.tree = txn.CommitOnly()
	return m
}

// Map of key-value pairs.
//
// Map is a typed wrapper around Tree[T] for working with
// keys that are not []byte.
type Map[K, V any] struct {
	toBytes   func(K) []byte
	fromBytes func([]byte) K
	tree      *Tree[V]
}

// ensureTree checks that the tree is not nil and allocates it if
// it is. The whole nil tree thing is to make sure that creating
// an empty map does not allocate anything.
func (m *Map[K, V]) ensureTree() {
	if m.tree == nil {
		m.tree = New[V](RootOnlyWatch)
	}
}

// Get a value from the map by its key.
func (m Map[K, V]) Get(key K) (value V, found bool) {
	if m.tree == nil {
		return
	}
	value, _, found = m.tree.Get(m.toBytes(key))
	return
}

// Set a value. Returns a new map with the value set.
// Original map is unchanged.
func (m Map[K, V]) Set(key K, value V) Map[K, V] {
	m.ensureTree()
	txn := m.tree.Txn()
	txn.Insert(m.toBytes(key), value)
	m.tree = txn.CommitOnly()
	return m
}

// Delete a value from the map. Returns a new map
// without the element pointed to by the key (if found).
func (m Map[K, V]) Delete(key K) Map[K, V] {
	if m.tree != nil {
		_, _, tree := m.tree.Delete(m.toBytes(key))
		// Map is a struct passed by value, so we can modify
		// it without changing the caller's view of it.
		m.tree = tree
	}
	return m
}

// LowerBound iterates over all keys in order with value equal
// to or greater than [from].
func (m Map[K, V]) LowerBound(from K) MapIterator[K, V] {
	if m.tree == nil {
		return MapIterator[K, V]{}
	}
	return MapIterator[K, V]{
		fromBytes: m.fromBytes,
		iter:      m.tree.LowerBound(m.toBytes(from)),
	}
}

// Prefix iterates in order over all keys that start with
// the given prefix.
func (m Map[K, V]) Prefix(prefix K) MapIterator[K, V] {
	if m.tree == nil {
		return MapIterator[K, V]{}
	}
	iter, _ := m.tree.Prefix(m.toBytes(prefix))
	return MapIterator[K, V]{
		fromBytes: m.fromBytes,
		iter:      iter,
	}
}

// All iterates every key-value in the map in order.
// The order is in bytewise order of the byte slice
// returned by toBytes.
func (m Map[K, V]) All() MapIterator[K, V] {
	if m.tree == nil {
		return MapIterator[K, V]{}
	}
	return MapIterator[K, V]{
		fromBytes: m.fromBytes,
		iter:      m.tree.Iterator(),
	}
}

// Len returns the number of elements in the map.
func (m Map[K, V]) Len() int {
	if m.tree == nil {
		return 0
	}
	return m.tree.size
}
