// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package set

// SliceSubsetOf checks whether the first slice is a subset of the second slice. If
// not, it also returns slice of elements which are the difference of both
// input slices.
func SliceSubsetOf(sub, main []string) (bool, []string) {
	if len(sub) == 0 {
		return true, nil
	}
	if len(main) == 0 {
		return len(sub) == 0, sub
	}

	var diff []string
	occurrences := make(map[string]int, len(main))
	result := true
	for _, element := range main {
		occurrences[element]++
	}
	for _, element := range sub {
		if count, ok := occurrences[element]; !ok {
			// Element was not found in the main slice.
			result = false
			diff = append(diff, element)
		} else if count < 1 {
			// The element is in both slices, but the sub slice
			// has more duplicates.
			result = false
		} else {
			occurrences[element]--
		}
	}
	return result, diff
}
