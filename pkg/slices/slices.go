// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package slices

import (
	"sort"

	"golang.org/x/exp/constraints"
	"golang.org/x/exp/slices"
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
