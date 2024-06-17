// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Set is a persistent (immutable) set of values. A Set can be
// defined for any type for which a byte slice key can be derived.
//
// A zero value Set[T] can be used provided that the conversion
// function for T have been registered with RegisterKeyType.
// For Set-only use only [bytesFromKey] needs to be defined.
type Set[T any] struct {
	toBytes func(T) []byte
	tree    *Tree[T]
}

// NewSet creates a new set of T.
// The value type T must be registered with RegisterKeyType.
func NewSet[T any](values ...T) Set[T] {
	s := Set[T]{tree: New[T](RootOnlyWatch)}
	s.toBytes = lookupKeyType[T]()
	if len(values) > 0 {
		txn := s.tree.Txn()
		for _, v := range values {
			txn.Insert(s.toBytes(v), v)
		}
		s.tree = txn.CommitOnly()
	}
	return s
}

// Set a value. Returns a new set. Original is unchanged.
func (s Set[T]) Set(v T) Set[T] {
	if s.tree == nil {
		return NewSet(v)
	}
	_, _, tree := s.tree.Insert(s.toBytes(v), v)
	s.tree = tree // As Set is passed by value we can just modify it.
	return s
}

// Delete returns a new set without the value. The original
// set is unchanged.
func (s Set[T]) Delete(v T) Set[T] {
	if s.tree == nil {
		return s
	}
	_, _, tree := s.tree.Delete(s.toBytes(v))
	s.tree = tree
	return s
}

// Has returns true if the set has the value.
func (s Set[T]) Has(v T) bool {
	if s.tree == nil {
		return false
	}
	_, _, found := s.tree.Get(s.toBytes(v))
	return found
}

// All returns an iterator for all values.
func (s Set[T]) All() SetIterator[T] {
	if s.tree == nil {
		return SetIterator[T]{nil}
	}
	return SetIterator[T]{s.tree.Iterator()}
}

// Union returns a set that is the union of the values
// in the input sets.
func (s Set[T]) Union(s2 Set[T]) Set[T] {
	if s2.tree == nil {
		return s
	}
	if s.tree == nil {
		return s2
	}
	txn := s.tree.Txn()
	iter := s2.tree.Iterator()
	for k, v, ok := iter.Next(); ok; k, v, ok = iter.Next() {
		txn.Insert(k, v)
	}
	s.tree = txn.CommitOnly()
	return s
}

// Difference returns a set with values that only
// appear in the first set.
func (s Set[T]) Difference(s2 Set[T]) Set[T] {
	if s.tree == nil || s2.tree == nil {
		return s
	}

	txn := s.tree.Txn()
	iter := s2.tree.Iterator()
	for k, _, ok := iter.Next(); ok; k, _, ok = iter.Next() {
		txn.Delete(k)
	}
	s.tree = txn.CommitOnly()
	return s
}

// Len returns the number of values in the set.
func (s Set[T]) Len() int {
	if s.tree == nil {
		return 0
	}
	return s.tree.size
}

// Equal returns true if the two sets contain the equal keys.
func (s Set[T]) Equal(other Set[T]) bool {
	switch {
	case s.tree == nil && other.tree == nil:
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

// Slice converts the set into a slice.
// Note that this allocates a new slice and appends
// all values into it. If you just want to iterate over
// the set use All() instead.
func (s Set[T]) Slice() []T {
	if s.tree == nil {
		return nil
	}
	xs := make([]T, 0, s.Len())
	iter := s.All()
	for v, ok := iter.Next(); ok; v, ok = iter.Next() {
		xs = append(xs, v)
	}
	return xs
}

// ToBytesFunc returns the function to extract the key from
// the element type. Useful for utilities that are interested
// in the key.
func (s Set[T]) ToBytesFunc() func(T) []byte {
	return s.toBytes
}

func (s Set[T]) MarshalJSON() ([]byte, error) {
	if s.tree == nil {
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

	if s.tree == nil {
		*s = NewSet[T]()
	}
	txn := s.tree.Txn()

	for dec.More() {
		var x T
		err := dec.Decode(&x)
		if err != nil {
			return err
		}
		txn.Insert(s.toBytes(x), x)
	}
	s.tree = txn.CommitOnly()

	t, err = dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != ']' {
		return fmt.Errorf("%T.UnmarshalJSON: expected ']' got %v", s, t)
	}
	return nil
}

// SetIterator iterates over values in a set.
type SetIterator[T any] struct {
	iter *Iterator[T]
}

// Next returns the next value or false if all have
// been iterated over.
func (it SetIterator[T]) Next() (v T, ok bool) {
	if it.iter == nil {
		return
	}
	_, v, ok = it.iter.Next()
	return
}
