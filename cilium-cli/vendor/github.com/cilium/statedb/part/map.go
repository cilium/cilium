// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
)

// Map of key-value pairs. The zero value is ready for use, provided
// that the key type has been registered with RegisterKeyType.
//
// Map is a typed wrapper around Tree[T] for working with
// keys that are not []byte.
type Map[K, V any] struct {
	bytesFromKey func(K) []byte
	tree         *Tree[mapKVPair[K, V]]
}

type mapKVPair[K, V any] struct {
	Key   K `json:"k"`
	Value V `json:"v"`
}

// FromMap copies values from the hash map into the given Map.
// This is not implemented as a method on Map[K,V] as hash maps require the
// comparable constraint and we do not need to limit Map[K, V] to that.
func FromMap[K comparable, V any](m Map[K, V], hm map[K]V) Map[K, V] {
	m.ensureTree()
	txn := m.tree.Txn()
	for k, v := range hm {
		txn.Insert(m.bytesFromKey(k), mapKVPair[K, V]{k, v})
	}
	m.tree = txn.CommitOnly()
	return m
}

// ensureTree checks that the tree is not nil and allocates it if
// it is. The whole nil tree thing is to make sure that creating
// an empty map does not allocate anything.
func (m *Map[K, V]) ensureTree() {
	if m.tree == nil {
		m.tree = New[mapKVPair[K, V]](RootOnlyWatch)
	}
	m.bytesFromKey = lookupKeyType[K]()
}

// Get a value from the map by its key.
func (m Map[K, V]) Get(key K) (value V, found bool) {
	if m.tree == nil {
		return
	}
	kv, _, found := m.tree.Get(m.bytesFromKey(key))
	return kv.Value, found
}

// Set a value. Returns a new map with the value set.
// Original map is unchanged.
func (m Map[K, V]) Set(key K, value V) Map[K, V] {
	m.ensureTree()
	txn := m.tree.Txn()
	txn.Insert(m.bytesFromKey(key), mapKVPair[K, V]{key, value})
	m.tree = txn.CommitOnly()
	return m
}

// Delete a value from the map. Returns a new map
// without the element pointed to by the key (if found).
func (m Map[K, V]) Delete(key K) Map[K, V] {
	if m.tree != nil {
		_, _, tree := m.tree.Delete(m.bytesFromKey(key))
		// Map is a struct passed by value, so we can modify
		// it without changing the caller's view of it.
		m.tree = tree
	}
	return m
}

// MapIterator iterates over key and value pairs.
type MapIterator[K, V any] struct {
	iter *Iterator[mapKVPair[K, V]]
}

// Next returns the next key (as bytes) and value. If the iterator
// is exhausted it returns false.
func (it MapIterator[K, V]) Next() (k K, v V, ok bool) {
	if it.iter == nil {
		return
	}
	_, kv, ok := it.iter.Next()
	return kv.Key, kv.Value, ok
}

// LowerBound iterates over all keys in order with value equal
// to or greater than [from].
func (m Map[K, V]) LowerBound(from K) MapIterator[K, V] {
	if m.tree == nil {
		return MapIterator[K, V]{}
	}
	return MapIterator[K, V]{
		iter: m.tree.LowerBound(m.bytesFromKey(from)),
	}
}

// Prefix iterates in order over all keys that start with
// the given prefix.
func (m Map[K, V]) Prefix(prefix K) MapIterator[K, V] {
	if m.tree == nil {
		return MapIterator[K, V]{}
	}
	iter, _ := m.tree.Prefix(m.bytesFromKey(prefix))
	return MapIterator[K, V]{
		iter: iter,
	}
}

// All iterates every key-value in the map in order.
// The order is in bytewise order of the byte slice
// returned by bytesFromKey.
func (m Map[K, V]) All() MapIterator[K, V] {
	if m.tree == nil {
		return MapIterator[K, V]{}
	}
	return MapIterator[K, V]{
		iter: m.tree.Iterator(),
	}
}

// EqualKeys returns true if both maps contain the same keys.
func (m Map[K, V]) EqualKeys(other Map[K, V]) bool {
	switch {
	case m.tree == nil && other.tree == nil:
		return true
	case m.Len() != other.Len():
		return false
	default:
		iter1 := m.tree.Iterator()
		iter2 := other.tree.Iterator()
		for {
			k1, _, ok := iter1.Next()
			if !ok {
				break
			}
			k2, _, _ := iter2.Next()
			// Equal lengths, no need to check 'ok' for 'iter2'.
			if !bytes.Equal(k1, k2) {
				return false
			}
		}
		return true
	}
}

// SlowEqual returns true if the two maps contain the same keys and values.
// Value comparison is implemented with reflect.DeepEqual which makes this
// slow and mostly useful for testing.
func (m Map[K, V]) SlowEqual(other Map[K, V]) bool {
	switch {
	case m.tree == nil && other.tree == nil:
		return true
	case m.Len() != other.Len():
		return false
	default:
		iter1 := m.tree.Iterator()
		iter2 := other.tree.Iterator()
		for {
			k1, v1, ok := iter1.Next()
			if !ok {
				break
			}
			k2, v2, _ := iter2.Next()
			// Equal lengths, no need to check 'ok' for 'iter2'.
			if !bytes.Equal(k1, k2) || !reflect.DeepEqual(v1, v2) {
				return false
			}
		}
		return true
	}
}

// Len returns the number of elements in the map.
func (m Map[K, V]) Len() int {
	if m.tree == nil {
		return 0
	}
	return m.tree.size
}

func (m Map[K, V]) MarshalJSON() ([]byte, error) {
	if m.tree == nil {
		return []byte("[]"), nil
	}

	var b bytes.Buffer
	b.WriteRune('[')
	iter := m.tree.Iterator()
	_, kv, ok := iter.Next()
	for ok {
		bs, err := json.Marshal(kv)
		if err != nil {
			return nil, err
		}
		b.Write(bs)
		_, kv, ok = iter.Next()
		if ok {
			b.WriteRune(',')
		}
	}
	b.WriteRune(']')
	return b.Bytes(), nil
}

func (m *Map[K, V]) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("%T.UnmarshalJSON: expected '[' got %v", m, t)
	}
	m.ensureTree()
	txn := m.tree.Txn()
	for dec.More() {
		var kv mapKVPair[K, V]
		err := dec.Decode(&kv)
		if err != nil {
			return err
		}
		txn.Insert(m.bytesFromKey(kv.Key), mapKVPair[K, V]{kv.Key, kv.Value})
	}

	t, err = dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != ']' {
		return fmt.Errorf("%T.UnmarshalJSON: expected ']' got %v", m, t)
	}
	m.tree = txn.CommitOnly()
	return nil
}
