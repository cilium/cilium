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
	toBytes func(T) []byte
	tree    Tree[T]
	hasTree bool
}

// NewSet creates a new set of T.
// The value type T must be registered with RegisterKeyType.
func NewSet[T any](values ...T) Set[T] {
	if len(values) == 0 {
		return Set[T]{}
	}
	s := Set[T]{}
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
	s.toBytes = lookupKeyType[T]()
}

// Set a value. Returns a new set. Original is unchanged.
func (s Set[T]) Set(v T) Set[T] {
	s.ensureTree()
	txn := s.tree.Txn()
	txn.Insert(s.toBytes(v), v)
	s.tree = txn.Commit() // As Set is passed by value we can just modify it.
	return s
}

// Delete returns a new set without the value. The original
// set is unchanged.
func (s Set[T]) Delete(v T) Set[T] {
	if !s.hasTree {
		return s
	}
	txn := s.tree.Txn()
	txn.Delete(s.toBytes(v))
	s.tree = txn.Commit()
	if s.tree.Len() == 0 {
		s.tree = Tree[T]{}
		s.hasTree = false
	}
	return s
}

// Has returns true if the set has the value.
func (s Set[T]) Has(v T) bool {
	if !s.hasTree {
		return false
	}
	_, _, found := s.tree.Get(s.toBytes(v))
	return found
}

func emptySeq[T any](yield func(T) bool) {
}

// All returns an iterator for all values.
func (s Set[T]) All() iter.Seq[T] {
	if !s.hasTree {
		return emptySeq[T]
	}
	return s.yieldAll
}

func (s Set[T]) yieldAll(yield func(v T) bool) {
	for _, v := range s.tree.Iterator().All {
		yield(v)
	}
}

// Union returns a set that is the union of the values
// in the input sets.
func (s Set[T]) Union(s2 Set[T]) Set[T] {
	if !s2.hasTree {
		return s
	}
	if !s.hasTree {
		return s2
	}
	txn := s.tree.Txn()
	iter := s2.tree.Iterator()
	for k, v, ok := iter.Next(); ok; k, v, ok = iter.Next() {
		txn.Insert(k, v)
	}
	s.tree = txn.Commit()
	return s
}

// Difference returns a set with values that only
// appear in the first set.
func (s Set[T]) Difference(s2 Set[T]) Set[T] {
	if !s.hasTree || !s2.hasTree {
		return s
	}

	txn := s.tree.Txn()
	iter := s2.tree.Iterator()
	for k, _, ok := iter.Next(); ok; k, _, ok = iter.Next() {
		txn.Delete(k)
	}
	s.tree = txn.Commit()
	return s
}

// Len returns the number of values in the set.
func (s Set[T]) Len() int {
	if !s.hasTree {
		return 0
	}
	return s.tree.size
}

// Equal returns true if the two sets contain the equal keys.
func (s Set[T]) Equal(other Set[T]) bool {
	switch {
	case !s.hasTree && !other.hasTree:
		return true
	case s.Len() != other.Len():
		return false
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
	if !s.hasTree {
		return []byte("[]"), nil
	}
	var b bytes.Buffer
	b.WriteRune('[')
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
	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("%T.UnmarshalJSON: expected '[' got %v", s, t)
	}

	*s = Set[T]{}
	s.ensureTree()
	txn := s.tree.Txn()

	for dec.More() {
		var x T
		err := dec.Decode(&x)
		if err != nil {
			return err
		}
		txn.Insert(s.toBytes(x), x)
	}
	s.tree = txn.Commit()
	if s.tree.Len() == 0 {
		s.tree = Tree[T]{}
		s.hasTree = false
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
