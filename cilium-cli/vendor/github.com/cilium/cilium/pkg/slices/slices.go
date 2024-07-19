// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package slices

import (
	"slices"
	"sort"

	"golang.org/x/exp/constraints"
)

// Unique deduplicates the elements in the input slice, preserving their ordering and
// modifying the slice in place.
// Unique relies on a map to find multiple occurrences of the same elements.
// For slices with a size less than 192 elements, a simpler O(N^2) search algorithm
// that does not allocate memory is used instead.
// Limit of 192 has been experimentally derived (look at BenchmarkUnique for more information).
func Unique[S ~[]T, T comparable](s S) S {
	if len(s) < 2 {
		return s
	}

	last := 0

	if len(s) < 192 {
	Loop:
		for i := 0; i < len(s); i++ {
			for j := 0; j < last; j++ {
				if s[i] == s[j] {
					continue Loop
				}
			}
			s[last] = s[i]
			last++
		}
	} else {
		set := make(map[T]struct{}, len(s))
		for i := 0; i < len(s); i++ {
			if _, ok := set[s[i]]; ok {
				continue
			}
			set[s[i]] = struct{}{}
			s[last] = s[i]
			last++
		}
	}

	return s[:last]
}

// UniqueFunc deduplicates the elements in the input slice like Unique, but takes a
// function to extract the comparable "key" to compare T. This is slower than Unique,
// but can be used with non-comparable elements.
func UniqueFunc[S ~[]T, T any, K comparable](s S, key func(i int) K) S {
	if len(s) < 2 {
		return s
	}

	last := 0

	set := make(map[K]struct{}, len(s))
	for i := 0; i < len(s); i++ {
		if _, ok := set[key(i)]; ok {
			continue
		}
		set[key(i)] = struct{}{}
		s[last] = s[i]
		last++
	}

	return s[:last]
}

// SortedUnique sorts and dedup the input slice in place.
// It uses the < operator to compare the elements in the slice and thus requires
// the elements to satisfies contraints.Ordered.
func SortedUnique[S ~[]T, T constraints.Ordered](s S) S {
	if len(s) < 2 {
		return s
	}

	sort.Slice(s, func(i, j int) bool {
		return s[i] < s[j]
	})
	return slices.Compact(s)
}

// SortedUniqueFunc is like SortedUnique but allows the user to specify custom functions
// for ordering (less function) and comparing (eq function) the elements in the slice.
// This is useful in all the cases where SortedUnique cannot be used:
// - for types that do not satisfy constraints.Ordered (e.g: composite types)
// - when the user wants to customize how elements are compared (e.g: user wants to enforce reverse ordering)
func SortedUniqueFunc[S ~[]T, T any](
	s S,
	less func(i, j int) bool,
	eq func(a, b T) bool,
) S {
	if len(s) < 2 {
		return s
	}

	sort.Slice(s, less)
	return slices.CompactFunc(s, eq)
}

// Diff returns a slice of elements which is the difference of a and b.
// The returned slice keeps the elements in the same order found in the "a" slice.
// Both input slices are considered as sets, that is, all elements are considered as
// unique when computing the difference.
func Diff[S ~[]T, T comparable](a, b S) []T {
	if len(a) == 0 {
		return nil
	}
	if len(b) == 0 {
		return a
	}

	var diff []T

	setB := make(map[T]struct{}, len(b))
	for _, v := range b {
		setB[v] = struct{}{}
	}

	setA := make(map[T]struct{}, len(a))
	for _, v := range a {
		// v is in b, too
		if _, ok := setB[v]; ok {
			continue
		}
		// v has been already added to diff
		if _, ok := setA[v]; ok {
			continue
		}
		diff = append(diff, v)
		setA[v] = struct{}{}
	}
	return diff
}

// SubsetOf returns a boolean that indicates if slice a is a subset of slice b.
// In case it is not, the returned slice contains all the unique elements that are in a but not in b.
func SubsetOf[S ~[]T, T comparable](a, b S) (bool, []T) {
	d := Diff(a, b)
	return len(d) == 0, d
}

// XorNil returns true if one of the two slices is nil while the other is not.
func XorNil[T any](s1, s2 []T) bool {
	return s1 == nil && s2 != nil ||
		s1 != nil && s2 == nil
}
