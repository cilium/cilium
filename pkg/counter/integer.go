// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

import (
	"sort"
)

// IntCounter tracks references for integers with an optional limiter.
//
// No threadsafety is provided within this structure, the user is expected to
// handle concurrent access to this structure if it is used from multiple
// threads.
type IntCounter Counter[int]

// Add increments the reference count for the specified integer key.
func (i IntCounter) Add(key int) (changed bool) {
	return Counter[int](i).Add(key)
}

// Delete decrements the reference count for the specified integer key.
func (i IntCounter) Delete(key int) bool {
	return Counter[int](i).Delete(key)
}

// DeepCopy makes a new copy of the received IntCounter.
func (i IntCounter) DeepCopy() IntCounter {
	return IntCounter(Counter[int](i).DeepCopy())
}

// ToBPFData returns the keys as a slice, sorted from high to low.
func (i IntCounter) ToBPFData() []int {
	result := make([]int, 0, len(i))
	for key := range i {
		result = append(result, key)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(result)))
	return result
}
