// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

// Set is a persistent (immutable) set of values. A Set can be
// defined for any type for which a byte slice key can be derived.
type Set[T any] struct {
	toBytes func(T) []byte
	tree    *Tree[T]
}

// NewSet creates a new set of T when given a function to convert T
// into a byte slice key.
func NewSet[T any](toBytes func(T) []byte, values ...T) Set[T] {
	if len(values) == 0 {
		return Set[T]{toBytes, nil}
	}

	s := Set[T]{toBytes, New[T](RootOnlyWatch)}
	txn := s.tree.Txn()
	for _, v := range values {
		txn.Insert(toBytes(v), v)
	}
	s.tree = txn.CommitOnly()
	return s
}

// StringSet is an empty set of strings.
// Short form for "part.NewStringSet()"
var StringSet = NewStringSet()

// NewStringSet creates a new set of strings.
func NewStringSet(values ...string) Set[string] {
	return NewSet(
		func(s string) []byte { return []byte(s) },
		values...,
	)
}

// BytesSet is an empty set of byte slices.
// Short form for "part.NewBytesSet()"
var BytesSet = NewBytesSet()

// NewBytesSet creates a new set of byte slices.
func NewBytesSet(values ...[]byte) Set[[]byte] {
	identity := func(b []byte) []byte { return b }
	return NewSet(identity, values...)
}

// Set a value. Returns a new set. Original is unchanged.
func (s Set[T]) Set(v T) Set[T] {
	if s.tree == nil {
		s.tree = New[T]()
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

// Union combines the values in the two sets. Returns a new set.
func (s Set[T]) Union(s2 Set[T]) Set[T] {
	txn := s.tree.Txn()
	iter := s2.tree.Iterator()
	for k, v, ok := iter.Next(); ok; k, v, ok = iter.Next() {
		txn.Insert(k, v)
	}
	s.tree = txn.CommitOnly()
	return s
}

// Difference removes the values in the second set from the first
// set. Returns a new set, the original sets are unchanged.
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

// Slice converts the set into a slice.
// Note that this allocates a new slice and appends
// all values into it. If you just want to iterate over
// the set use All() instead.
func (s Set[T]) Slice() []T {
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
