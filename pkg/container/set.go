// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import "golang.org/x/exp/maps"

// Set is a mutable type-safe unordered set built around the built-in
// hash map (map[T]struct{}). It is not safe for concurrent use.
type Set[T comparable] map[T]struct{}

// NewSet creates a new set
func NewSet[T comparable](items ...T) Set[T] {
	set := make(Set[T], len(items))
	for i := range items {
		set[items[i]] = struct{}{}
	}
	return set
}

// Empty returns true if the set is empty
func (s Set[T]) Empty() bool {
	return len(s) == 0
}

// Len returns the number of items in the set
func (s Set[T]) Len() int {
	return len(s)
}

// Add items to the set
// O(1).
func (s Set[T]) Add(items ...T) {
	for _, item := range items {
		s[item] = struct{}{}
	}
}

// Delete items from the set
// O(1) per item.
func (s Set[T]) Delete(items ...T) {
	for _, item := range items {
		delete(s, item)
	}
}

// Contains returns true if the item is part of the set.
// O(1).
func (s Set[T]) Contains(item T) bool {
	_, ok := s[item]
	return ok
}

// Slice returns the set as a slice. Unsorted.
// O(n)
func (s Set[T]) Slice() []T {
	return maps.Keys(s)
}

// Clone returns a clone of the set.
// O(n).
func (s Set[T]) Clone() Set[T] {
	return maps.Clone(s)
}

// Union a set with another set. Modifies and returns itself.
// O(n).
func (s Set[T]) Union(other Set[T]) Set[T] {
	for item := range other {
		s.Add(item)
	}
	return s
}

// Sub substracts from itself the items in the given set.
// O(n).
func (s Set[T]) Sub(other Set[T]) Set[T] {
	for item := range other {
		delete(s, item)
	}
	return s
}
