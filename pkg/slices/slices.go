// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package slices

import (
	"cmp"
	"slices"
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
		for i := range len(s) {
			for j := range last {
				if s[i] == s[j] {
					continue Loop
				}
			}
			s[last] = s[i]
			last++
		}
	} else {
		set := make(map[T]struct{}, len(s))
		for i := range len(s) {
			if _, ok := set[s[i]]; ok {
				continue
			}
			set[s[i]] = struct{}{}
			s[last] = s[i]
			last++
		}
	}

	clear(s[last:]) // zero out obsolete elements for GC
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
	for i := range len(s) {
		if _, ok := set[key(i)]; ok {
			continue
		}
		set[key(i)] = struct{}{}
		s[last] = s[i]
		last++
	}

	clear(s[last:]) // zero out obsolete elements for GC
	return s[:last]
}

// SortedUnique sorts and dedup the input slice in place.
// It uses the < operator to compare the elements in the slice and thus requires
// the elements to satisfies contraints.Ordered.
func SortedUnique[S ~[]T, T cmp.Ordered](s S) S {
	if len(s) < 2 {
		return s
	}

	slices.Sort(s)
	return slices.Compact(s)
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

// AllMatch returns true if pred is true for each element in s, false otherwise.
// May not evaluate on all elements if not necessary for determining the result.
// If the slice is empty then true is returned and predicate is not evaluated.
func AllMatch[T any](s []T, pred func(v T) bool) bool {
	for _, v := range s {
		if !pred(v) {
			return false
		}
	}
	return true
}
