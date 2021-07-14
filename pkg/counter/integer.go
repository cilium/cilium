// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package counter

import (
	"sort"
)

// IntCounter tracks references for integers with an optional limiter.
//
// No threadsafety is provided within this structure, the user is expected to
// handle concurrent access to this structure if it is used from multiple
// threads.
type IntCounter map[int]int

// DeepCopy makes a new copy of the received IntCounter.
func (i IntCounter) DeepCopy() IntCounter {
	result := make(IntCounter, len(i))
	for k, v := range i {
		result[k] = v
	}
	return result
}

// Add increments the reference count for the specified integer key.
func (i IntCounter) Add(key int) (changed bool) {
	value, exists := i[key]
	if !exists {
		changed = true
	}
	i[key] = value + 1
	return changed
}

// Delete decrements the reference count for the specified integer key.
func (i IntCounter) Delete(key int) bool {
	value := i[key]
	if value <= 1 {
		delete(i, key)
		return true
	}
	i[key] = value - 1
	return false
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
