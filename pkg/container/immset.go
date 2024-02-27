// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"cmp"
	"slices"

	"golang.org/x/exp/constraints"
)

// ImmSet is an immutable set optimized for a smallish (1-1000) set of items.
// Implemented as a sorted slice.
type ImmSet[T any] struct {
	xs  []T
	cmp func(T, T) int
	eq  func(T, T) bool
}

func NewImmSet[T constraints.Ordered](items ...T) ImmSet[T] {
	return NewImmSetFunc[T](cmp.Compare, items...)
}

func NewImmSetFunc[T any](compare func(T, T) int, items ...T) ImmSet[T] {
	s := ImmSet[T]{items, compare, cmpToEqual(compare)}
	slices.SortFunc(s.xs, s.cmp)
	s.xs = slices.CompactFunc(s.xs, s.eq)
	return s
}

// AsSlice returns the underlying slice stored in the immutable set.
// The caller is NOT allowed to modify the slice.
func (s ImmSet[T]) AsSlice() []T {
	return s.xs
}

func (s ImmSet[T]) Len() int {
	return len(s.xs)
}

func (s ImmSet[T]) Has(x T) bool {
	_, found := slices.BinarySearchFunc(s.xs, x, s.cmp)
	return found
}

func (s ImmSet[T]) Insert(xs ...T) ImmSet[T] {
	xs2 := make([]T, 0, len(s.xs)+len(xs))
	xs2 = append(xs2, s.xs...)
	for _, x := range xs {
		idx, found := slices.BinarySearchFunc(s.xs, x, s.cmp)
		if !found {
			xs2 = slices.Insert(xs2, idx, x)
		}
	}
	return ImmSet[T]{xs: xs2, cmp: s.cmp, eq: s.eq}
}

func (s ImmSet[T]) Delete(xs ...T) ImmSet[T] {
	s.xs = slices.Clone(s.xs)
	for _, x := range xs {
		idx, found := slices.BinarySearchFunc(s.xs, x, s.cmp)
		if found {
			s.xs = slices.Delete(s.xs, idx, idx+1)
		}
	}
	return s
}

func (s ImmSet[T]) Union(s2 ImmSet[T]) ImmSet[T] {
	result := make([]T, len(s.xs)+len(s2.xs))
	copy(result, s.xs)
	copy(result[len(s.xs):], s2.xs)
	slices.SortFunc(s.xs, s.cmp)
	result = slices.CompactFunc(result, s.eq)
	return ImmSet[T]{result, s.cmp, s.eq}
}

func (s ImmSet[T]) Difference(s2 ImmSet[T]) ImmSet[T] {
	return s.Delete(s2.xs...)
}

func (s ImmSet[T]) Equal(s2 ImmSet[T]) bool {
	return slices.EqualFunc(s.xs, s2.xs, s.eq)
}

func cmpToEqual[T any](cmp func(T, T) int) func(T, T) bool {
	return func(a, b T) bool {
		return cmp(a, b) == 0
	}
}
