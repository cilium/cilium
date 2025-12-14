// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"bytes"
	"encoding/json"
	"fmt"
	"iter"
	"reflect"

	"go.yaml.in/yaml/v3"
)

// Map of key-value pairs. The zero value is ready for use, provided
// that the key type has been registered with RegisterKeyType.
//
// Map is a typed wrapper around Tree[T] for working with
// keys that are not []byte.
type Map[K, V any] struct {
	bytesFromKeyFunc func(K) []byte
	tree             *Tree[mapKVPair[K, V]]
	singleton        *mapKVPair[K, V]
}

type mapKVPair[K, V any] struct {
	Key   K `json:"k" yaml:"k"`
	Value V `json:"v" yaml:"v"`
}

// FromMap copies values from the hash map into the given Map.
// This is not implemented as a method on Map[K,V] as hash maps require the
// comparable constraint and we do not need to limit Map[K, V] to that.
func FromMap[K comparable, V any](m Map[K, V], hm map[K]V) Map[K, V] {
	switch len(hm) {
	case 0:
		return m
	case 1:
		for key, value := range hm {
			return m.Set(key, value)
		}
	}

	m.ensureTree()
	txn := m.tree.Txn()
	for key, value := range hm {
		txn.Insert(m.keyToBytes(key), mapKVPair[K, V]{key, value})
	}
	if m.singleton != nil {
		txn.Insert(m.keyToBytes(m.singleton.Key), *m.singleton)
		m.singleton = nil
	}
	m.tree = txn.Commit()
	return m
}

// ensureTree checks that the tree is not nil and allocates it if
// it is. The whole nil tree thing is to make sure that creating
// an empty map does not allocate anything.
func (m *Map[K, V]) ensureTree() {
	if m.tree == nil {
		m.tree = New[mapKVPair[K, V]](RootOnlyWatch)
	}
}

// Get a value from the map by its key.
func (m Map[K, V]) Get(key K) (value V, found bool) {
	if m.singleton != nil && bytes.Equal(m.keyToBytes(m.singleton.Key), m.keyToBytes(key)) {
		return m.singleton.Value, true
	}

	if m.tree == nil {
		return
	}
	kv, _, found := m.tree.Get(m.keyToBytes(key))
	return kv.Value, found
}

// Set a value. Returns a new map with the value set.
// Original map is unchanged.
func (m Map[K, V]) Set(key K, value V) Map[K, V] {
	keyBytes := m.keyToBytes(key)
	if m.tree == nil && m.singleton == nil || m.singleton != nil && bytes.Equal(keyBytes, m.keyToBytes(m.singleton.Key)) {
		m.singleton = &mapKVPair[K, V]{key, value}
		return m
	}

	m.ensureTree()
	txn := m.tree.Txn()
	txn.Insert(keyBytes, mapKVPair[K, V]{key, value})
	if m.singleton != nil {
		txn.Insert(m.keyToBytes(m.singleton.Key), *m.singleton)
		m.singleton = nil
	}
	m.tree = txn.Commit()
	return m
}

func (m *Map[K, V]) keyToBytes(key K) []byte {
	if m.bytesFromKeyFunc == nil {
		m.bytesFromKeyFunc = lookupKeyType[K]()
	}
	return m.bytesFromKeyFunc(key)
}

// Delete a value from the map. Returns a new map
// without the element pointed to by the key (if found).
func (m Map[K, V]) Delete(key K) Map[K, V] {
	if m.singleton != nil {
		if bytes.Equal(m.keyToBytes(m.singleton.Key), m.keyToBytes(key)) {
			m.singleton = nil
		}
		return m
	}
	if m.tree != nil {
		txn := m.tree.Txn()
		txn.Delete(m.keyToBytes(key))
		switch txn.Len() {
		case 0:
			m.tree = nil
		case 1:
			_, kv, _ := txn.Iterator().Next()
			m.singleton = &kv
			m.tree = nil
		default:
			m.tree = txn.Commit()
		}
	}
	return m
}

func toSeq2[K, V any](iter *Iterator[mapKVPair[K, V]]) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		if iter == nil {
			return
		}
		iter = iter.Clone()
		for _, kv, ok := iter.Next(); ok; _, kv, ok = iter.Next() {
			if !yield(kv.Key, kv.Value) {
				break
			}
		}
	}
}

// LowerBound iterates over all keys in order with value equal
// to or greater than [from].
func (m Map[K, V]) LowerBound(from K) iter.Seq2[K, V] {
	if m.singleton != nil {
		if bytes.Compare(m.keyToBytes(m.singleton.Key), m.keyToBytes(from)) >= 0 {
			return m.singletonIter()
		}
	}
	if m.tree == nil {
		return toSeq2[K, V](nil)
	}
	return toSeq2(m.tree.LowerBound(m.keyToBytes(from)))
}

func (m *Map[K, V]) singletonIter() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		if m.singleton != nil {
			yield(m.singleton.Key, m.singleton.Value)
		}
	}
}

// Prefix iterates in order over all keys that start with
// the given prefix.
func (m Map[K, V]) Prefix(prefix K) iter.Seq2[K, V] {
	if m.singleton != nil {
		if bytes.HasPrefix(m.keyToBytes(m.singleton.Key), m.keyToBytes(prefix)) {
			return m.singletonIter()
		}
	}
	if m.tree == nil {
		return toSeq2[K, V](nil)
	}
	iter, _ := m.tree.Prefix(m.keyToBytes(prefix))
	return toSeq2(iter)
}

// All iterates every key-value in the map in order.
// The order is in bytewise order of the byte slice
// returned by bytesFromKey.
func (m Map[K, V]) All() iter.Seq2[K, V] {
	if m.singleton != nil {
		return m.singletonIter()
	}
	if m.tree == nil {
		return toSeq2[K, V](nil)
	}
	return toSeq2(m.tree.Iterator())
}

// EqualKeys returns true if both maps contain the same keys.
func (m Map[K, V]) EqualKeys(other Map[K, V]) bool {
	switch {
	case m.Len() != other.Len():
		return false
	case m.singleton != nil && other.singleton != nil:
		return bytes.Equal(m.keyToBytes(m.singleton.Key), other.keyToBytes(other.singleton.Key))
	case m.tree == nil && other.tree == nil:
		return true
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
	case m.Len() != other.Len():
		return false
	case m.singleton != nil && other.singleton != nil:
		return bytes.Equal(m.keyToBytes(m.singleton.Key), other.keyToBytes(other.singleton.Key)) &&
			reflect.DeepEqual(m.singleton.Value, other.singleton.Value)
	case m.tree == nil && other.tree == nil:
		return true
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
	if m.singleton != nil {
		return 1
	}
	if m.tree == nil {
		return 0
	}
	return m.tree.size
}

func (m Map[K, V]) MarshalJSON() ([]byte, error) {
	if m.tree == nil && m.singleton == nil {
		return []byte("[]"), nil
	}

	var b bytes.Buffer
	b.WriteRune('[')

	if m.singleton != nil {
		bs, err := json.Marshal(*m.singleton)
		if err != nil {
			return nil, err
		}
		b.Write(bs)
		b.WriteRune(']')
		return b.Bytes(), nil
	}

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
	*m = Map[K, V]{}

	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("%T.UnmarshalJSON: expected '[' got %v", m, t)
	}
	if !dec.More() {
		return nil
	}

	var kv mapKVPair[K, V]
	err = dec.Decode(&kv)
	if err != nil {
		return err
	}

	if !dec.More() {
		m.singleton = &kv
		return nil
	}

	m.ensureTree()
	txn := m.tree.Txn()
	txn.Insert(m.keyToBytes(kv.Key), kv)
	for dec.More() {
		var kv mapKVPair[K, V]
		err := dec.Decode(&kv)
		if err != nil {
			return err
		}
		txn.Insert(m.keyToBytes(kv.Key), kv)
	}
	t, err = dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != ']' {
		return fmt.Errorf("%T.UnmarshalJSON: expected ']' got %v", m, t)
	}
	m.tree = txn.Commit()
	return nil
}

func (m Map[K, V]) MarshalYAML() (any, error) {
	kvs := make([]mapKVPair[K, V], 0, m.Len())
	for k, v := range m.All() {
		kvs = append(kvs, mapKVPair[K, V]{k, v})
	}
	return kvs, nil
}

func (m *Map[K, V]) UnmarshalYAML(value *yaml.Node) error {
	*m = Map[K, V]{}

	if value.Kind != yaml.SequenceNode {
		return fmt.Errorf("%T.UnmarshalYAML: expected sequence", m)
	}
	switch len(value.Content) {
	case 0:
		return nil
	case 1:
		var kv mapKVPair[K, V]
		if err := value.Content[0].Decode(&kv); err != nil {
			return err
		}
		m.singleton = &kv
		return nil
	}

	m.ensureTree()
	txn := m.tree.Txn()
	for _, e := range value.Content {
		var kv mapKVPair[K, V]
		if err := e.Decode(&kv); err != nil {
			return err
		}
		txn.Insert(m.keyToBytes(kv.Key), mapKVPair[K, V]{kv.Key, kv.Value})
	}
	m.tree = txn.Commit()
	return nil
}

func (m Map[K, V]) Txn() MapTxn[K, V] {
	m.ensureTree()
	txn := m.tree.Txn()
	if m.singleton != nil {
		txn.Insert(m.keyToBytes(m.singleton.Key), mapKVPair[K, V]{m.singleton.Key, m.singleton.Value})
	}
	bytesFromKey := m.bytesFromKeyFunc
	if bytesFromKey == nil {
		bytesFromKey = lookupKeyType[K]()
	}
	return MapTxn[K, V]{
		bytesFromKeyFunc: bytesFromKey,
		txn:              txn,
	}
}

// MapTxn is a write transaction for efficiently doing multiple
// modifications to a map.
type MapTxn[K, V any] struct {
	bytesFromKeyFunc func(K) []byte
	txn              *Txn[mapKVPair[K, V]]
}

// Commit the transaction returning a new map.
// The transaction can be used again for further modifications.
func (txn MapTxn[K, V]) Commit() (m Map[K, V]) {
	m.bytesFromKeyFunc = txn.bytesFromKeyFunc
	switch txn.txn.Len() {
	case 0:
	case 1:
		_, kv, _ := txn.txn.Iterator().Next()
		m.singleton = &kv
	default:
		m.tree = txn.txn.Commit()
	}
	return
}

// Set a value.
func (txn MapTxn[K, V]) Set(key K, value V) {
	txn.txn.Insert(txn.bytesFromKeyFunc(key), mapKVPair[K, V]{key, value})
}

// Delete a value from the map.
// Returns true if the key was found.
func (txn MapTxn[K, V]) Delete(key K) bool {
	_, hadOld := txn.txn.Delete(txn.bytesFromKeyFunc(key))
	return hadOld
}

// Get a value from the map by its key.
func (txn MapTxn[K, V]) Get(key K) (value V, found bool) {
	kv, _, found := txn.txn.Get(txn.bytesFromKeyFunc(key))
	return kv.Value, found
}

// Prefix iterates in order over all keys that start with
// the given prefix.
func (txn MapTxn[K, V]) Prefix(prefix K) iter.Seq2[K, V] {
	iter, _ := txn.txn.Prefix(txn.bytesFromKeyFunc(prefix))
	return toSeq2(iter)
}

// LowerBound iterates over all keys in order with value equal
// to or greater than [from].
func (txn MapTxn[K, V]) LowerBound(from K) iter.Seq2[K, V] {
	return toSeq2(txn.txn.LowerBound(txn.bytesFromKeyFunc(from)))
}

// All iterates every key-value in the map in order.
// The order is in bytewise order of the byte slice
// returned by bytesFromKey.
func (txn MapTxn[K, V]) All() iter.Seq2[K, V] {
	return toSeq2(txn.txn.Iterator())
}

// Len returns the number of elements in the map.
func (txn MapTxn[K, V]) Len() int {
	return txn.txn.Len()
}
