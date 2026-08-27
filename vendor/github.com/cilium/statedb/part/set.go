// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"bytes"
	"encoding/json"
	"fmt"
	"iter"
	"slices"

	"go.yaml.in/yaml/v3"
)

// Set is a persistent (immutable) set of values. A Set can be
// defined for any type for which a byte slice key can be derived.
//
// A zero value Set[T] can be used provided that the conversion
// function for T have been registered with RegisterKeyType.
// For Set-only use only [bytesFromKey] needs to be defined.
type Set[T any] struct {
	toBytes   func(T) []byte
	singleton *T
	tree      Tree[T]
	hasTree   bool
}

// NewSet creates a new set of T.
// The value type T must be registered with RegisterKeyType.
func NewSet[T any](values ...T) Set[T] {
	if len(values) == 0 {
		return Set[T]{}
	}
	s := Set[T]{toBytes: lookupKeyType[T]()}
	if len(values) == 1 {
		value := values[0]
		s.singleton = &value
		return s
	}
	s.ensureTree()
	txn := s.tree.Txn()
	for _, v := range values {
		txn.Insert(s.toBytes(v), v)
	}
	s.tree = txn.Commit()
	return s
}

func (s *Set[T]) ensureTree() {
	if !s.hasTree {
		s.tree = New[T](RootOnlyWatch)
		s.hasTree = true
	}
	if s.toBytes == nil {
		s.toBytes = lookupKeyType[T]()
	}
}

func (s *Set[T]) keyToBytes(v T) []byte {
	if s.toBytes == nil {
		s.toBytes = lookupKeyType[T]()
	}
	return s.toBytes(v)
}

// Set a value. Returns a new set. Original is unchanged.
func (s Set[T]) Set(v T) Set[T] {
	key := s.keyToBytes(v)
	if (!s.hasTree && s.singleton == nil) ||
		(s.singleton != nil && bytes.Equal(key, s.keyToBytes(*s.singleton))) {
		s.singleton = &v
		return s
	}

	s.ensureTree()
	txn := s.tree.Txn()
	txn.Insert(key, v)
	if s.singleton != nil {
		txn.Insert(s.keyToBytes(*s.singleton), *s.singleton)
		s.singleton = nil
	}
	s.tree = txn.Commit() // As Set is passed by value we can just modify it.
	return s
}

// Delete returns a new set without the value. The original
// set is unchanged.
func (s Set[T]) Delete(v T) Set[T] {
	if s.singleton != nil {
		if bytes.Equal(s.keyToBytes(*s.singleton), s.keyToBytes(v)) {
			s.singleton = nil
		}
		return s
	}
	if !s.hasTree {
		return s
	}
	txn := s.tree.Txn()
	txn.Delete(s.keyToBytes(v))
	switch txn.Len() {
	case 0:
		s.tree = Tree[T]{}
		s.hasTree = false
	case 1:
		iter := txn.Iterator()
		_, value, _ := iter.Next()
		s.singleton = &value
		s.tree = Tree[T]{}
		s.hasTree = false
	default:
		s.tree = txn.Commit()
	}
	return s
}

// Has returns true if the set has the value.
func (s Set[T]) Has(v T) bool {
	if s.singleton != nil {
		return bytes.Equal(s.keyToBytes(*s.singleton), s.keyToBytes(v))
	}
	if !s.hasTree {
		return false
	}
	_, found := s.tree.Get(s.keyToBytes(v))
	return found
}

// First returns the first value in key order, or false if the set is empty.
func (s Set[T]) First() (value T, ok bool) {
	if s.singleton != nil {
		return *s.singleton, true
	}
	if !s.hasTree {
		return value, false
	}
	iter := s.tree.Iterator()
	_, value, ok = iter.Next()
	return value, ok
}

func emptySeq[T any](yield func(T) bool) {
}

// All returns an iterator for all values.
func (s Set[T]) All() iter.Seq[T] {
	if !s.hasTree && s.singleton == nil {
		return emptySeq[T]
	}
	return s.yieldAll
}

func (s Set[T]) yieldAll(yield func(v T) bool) {
	if s.singleton != nil {
		yield(*s.singleton)
		return
	}
	for _, v := range s.tree.Iterator().All {
		if !yield(v) {
			return
		}
	}
}

// Union returns a set that is the union of the values
// in the input sets.
func (s Set[T]) Union(s2 Set[T]) Set[T] {
	if s2.Len() == 0 {
		return s
	}
	if s.Len() == 0 {
		return s2
	}

	s.ensureTree()
	txn := s.tree.Txn()
	if s.singleton != nil {
		txn.Insert(s.keyToBytes(*s.singleton), *s.singleton)
		s.singleton = nil
	}
	if s2.singleton != nil {
		txn.Insert(s2.keyToBytes(*s2.singleton), *s2.singleton)
	} else {
		iter := s2.tree.Iterator()
		for k, v, ok := iter.Next(); ok; k, v, ok = iter.Next() {
			txn.Insert(k, v)
		}
	}
	s.tree = txn.Commit()
	return s
}

// Difference returns a set with values that only
// appear in the first set.
func (s Set[T]) Difference(s2 Set[T]) Set[T] {
	if s.Len() == 0 || s2.Len() == 0 {
		return s
	}
	if s.singleton != nil {
		if s2.Has(*s.singleton) {
			s.singleton = nil
		}
		return s
	}

	txn := s.tree.Txn()
	if s2.singleton != nil {
		txn.Delete(s2.keyToBytes(*s2.singleton))
	} else {
		iter := s2.tree.Iterator()
		for k, _, ok := iter.Next(); ok; k, _, ok = iter.Next() {
			txn.Delete(k)
		}
	}
	switch txn.Len() {
	case 0:
		s.tree = Tree[T]{}
		s.hasTree = false
	case 1:
		iter := txn.Iterator()
		_, value, _ := iter.Next()
		s.singleton = &value
		s.tree = Tree[T]{}
		s.hasTree = false
	default:
		s.tree = txn.Commit()
	}
	return s
}

// Len returns the number of values in the set.
func (s Set[T]) Len() int {
	if s.singleton != nil {
		return 1
	}
	if !s.hasTree {
		return 0
	}
	return s.tree.size
}

// Equal returns true if the two sets contain the equal keys.
func (s Set[T]) Equal(other Set[T]) bool {
	switch {
	case s.Len() != other.Len():
		return false
	case s.Len() == 0:
		return true
	case s.Len() == 1:
		v1, _ := s.First()
		v2, _ := other.First()
		return bytes.Equal(s.keyToBytes(v1), other.keyToBytes(v2))
	default:
		iter1 := s.tree.Iterator()
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

// ToBytesFunc returns the function to extract the key from
// the element type. Useful for utilities that are interested
// in the key.
func (s Set[T]) ToBytesFunc() func(T) []byte {
	return s.toBytes
}

func (s Set[T]) MarshalJSON() ([]byte, error) {
	if !s.hasTree && s.singleton == nil {
		return []byte("[]"), nil
	}
	var b bytes.Buffer
	b.WriteRune('[')
	if s.singleton != nil {
		bs, err := json.Marshal(*s.singleton)
		if err != nil {
			return nil, err
		}
		b.Write(bs)
		b.WriteRune(']')
		return b.Bytes(), nil
	}

	iter := s.tree.Iterator()
	_, v, ok := iter.Next()
	for ok {
		bs, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		b.Write(bs)
		_, v, ok = iter.Next()
		if ok {
			b.WriteRune(',')
		}
	}
	b.WriteRune(']')
	return b.Bytes(), nil
}

func (s *Set[T]) UnmarshalJSON(data []byte) error {
	*s = Set[T]{}

	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("%T.UnmarshalJSON: expected '[' got %v", s, t)
	}

	if !dec.More() {
		_, err = dec.Token()
		return err
	}

	var first T
	if err := dec.Decode(&first); err != nil {
		return err
	}
	if !dec.More() {
		s.toBytes = lookupKeyType[T]()
		s.singleton = &first
	} else {
		s.ensureTree()
		txn := s.tree.Txn()
		txn.Insert(s.keyToBytes(first), first)
		for dec.More() {
			var x T
			if err := dec.Decode(&x); err != nil {
				return err
			}
			txn.Insert(s.keyToBytes(x), x)
		}
		s.tree = txn.Commit()
	}

	t, err = dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != ']' {
		return fmt.Errorf("%T.UnmarshalJSON: expected ']' got %v", s, t)
	}
	return nil
}

func (s Set[T]) MarshalYAML() (any, error) {
	// TODO: Once yaml.v3 supports iter.Seq, drop the Collect().
	return slices.Collect(s.All()), nil
}

func (s *Set[T]) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.SequenceNode {
		return fmt.Errorf("%T.UnmarshalYAML: expected sequence", s)
	}

	*s = Set[T]{}
	switch len(value.Content) {
	case 0:
		return nil
	case 1:
		var v T
		if err := value.Content[0].Decode(&v); err != nil {
			return err
		}
		s.toBytes = lookupKeyType[T]()
		s.singleton = &v
		return nil
	}

	s.ensureTree()
	txn := s.tree.Txn()

	for _, e := range value.Content {
		var v T
		if err := e.Decode(&v); err != nil {
			return err
		}
		txn.Insert(s.toBytes(v), v)
	}
	s.tree = txn.Commit()
	return nil
}
