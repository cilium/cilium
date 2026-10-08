// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

// Package sparse provides a compact and efficient sparse array
// implementation for addressable key ranges from [0..255].
//
// It is optimized for use in radix tries and lookup structures
// where only a small subset of possible keys contain actual data.
//
// Internally, an Array256 combines a fixed-size BitSet256 with
// a compact packed Items slice. The bitset tracks which key slots
// are occupied and enables fast index mapping via popcount (Rank),
// while the Items slice stores the associated payloads.
//
// Lookup, insertion, and deletion operate in O(1) time (worst-case O(n)
// only for shifting/copying in extremely full arrays).
//
// This module avoids memory allocations where possible and provides
// predictable performance even under heavy insert/delete workloads.
package sparse

import (
	"github.com/gaissmai/bart/internal/bitset"
)

// Array256 is a popcount-compressed sparse array for up to 256 item slots.
//
// Internally, it consists of:
//   - a BitSet256, where each set bit marks a present slot (i.e., key i used)
//   - a compact Items slice, which stores the payloads only for the set bits
//
// Each occupied index i ∈ [0..255] can be tested using .Test(i).
// The actual index within the Items slice is computed via .Rank(i)-1.
//
// All insert/delete operations update both the bitset and item slice
// to preserve this mapping invariant. Direct mutation of the underlying
// bitset (via Set or Clear) is forbidden and will panic.
//
// This structure allows extremely fast and compact prefix-based routing,
// highly efficient child-node containers in prefix tries, or memory-safe
// alternatives to map[uint8]T with deterministic iteration.
//
// Example layout:
//
//	BitSet256:   [0 1 0 0 0 1 ...]   // bits 1 and 5 set
//	Items:       [T1, T2]            // a.Items[0] ↔ key 1, a.Items[1] ↔ key 5
type Array256[T any] struct {
	bitset.BitSet256
	Items []T
}

// Set panics. The bitset is internally coupled with Items[].
// Use InsertAt to add or overwrite at index i.
func (a *Array256[T]) Set(uint) {
	panic("forbidden, use InsertAt")
}

// Clear panics. The bitset is internally coupled with Items[].
func (a *Array256[T]) Clear(uint) {
	panic("forbidden, use DeleteAt")
}

// Get returns the value at index i and whether it exists.
//
// If the bit for i is not set, ok is false and value is the zero-value of T.
//
// example: a.Get(5) -> a.Items[1]
//
//	                        ⬇
//	BitSet256:   [0|0|1|0|0|1|0|...|1] <- 3 bits set
//	Items:       [*|*|*]               <- len(Items) = 3
//	                ⬆
//
//	BitSet256.Test(5):     true
//	BitSet256.Rank(5):     2,
func (a *Array256[T]) Get(i uint8) (value T, ok bool) {
	if a.Test(i) {
		return a.Items[a.Rank(i)-1], true
	}
	return
}

// MustGet returns the value at index i without checking if it exists.
//
// Use only after ensuring i is set (via Test(i)); otherwise it may return
// an incorrect value or panic. Intended only for tight, validated loops.
func (a *Array256[T]) MustGet(i uint8) T {
	return a.Items[a.Rank(i)-1]
}

// Len returns the number of items in sparse array.
func (a *Array256[T]) Len() int {
	return len(a.Items)
}

// Copy returns a shallow copy of the Array.
// The elements are copied using assignment, this is no deep clone.
func (a *Array256[T]) Copy() *Array256[T] {
	if a == nil {
		return nil
	}

	c := &Array256[T]{
		BitSet256: a.BitSet256,
		Items:     make([]T, len(a.Items)),
	}
	copy(c.Items, a.Items)
	return c
}

// InsertAt adds the value to the index i. If a value already exists there,
// it is overwritten and true is returned.
//
// Otherwise, the value is inserted, the bit is marked, and false returned.
func (a *Array256[T]) InsertAt(i uint8, value T) (exists bool) {
	// slot exists, overwrite value
	if a.Test(i) {
		a.Items[a.Rank(i)-1] = value
		return true
	}

	// new, insert into bitset ...
	a.BitSet256.Set(i)

	// ... and slice
	a.insertItem(a.Rank(i)-1, value)

	return false
}

// DeleteAt removes the value at index i from the sparse array,
// shifting remaining items down in the slice and clearing the bit.
//
// If the entry exists, it is returned together with true.
// If i is not present, the zero value and false are returned.
func (a *Array256[T]) DeleteAt(i uint8) (value T, exists bool) {
	if a.Len() == 0 || !a.Test(i) {
		return value, exists
	}

	rank0 := a.Rank(i) - 1
	value = a.Items[rank0]

	// delete from slice
	a.deleteItem(rank0)

	// delete from bitset
	a.BitSet256.Clear(i)

	return value, true
}

// insertItem inserts a new element at the given index position i in the Items slice,
// shifting all following elements one position to the right to make space.
//
// This method must be called with the correct insertion index - that is,
// the rank-0 value of the corresponding bit index i in BitSet256 once it's set.
//
// The slice will be extended by one element. If the capacity allows, this is done
// without reallocation (fast path); otherwise slice growth occurs (slow path).
//
// Example (inserting at rank0 == 2):
//
//	Items before: [A B C D]
//	After insertItem(2, X): [A B X C D]
//
// Panics if i is out of range (i < 0 or i > len(Items)).
func (a *Array256[T]) insertItem(i int, item T) {
	if len(a.Items) < cap(a.Items) {
		a.Items = a.Items[:len(a.Items)+1] // fast resize, no alloc
	} else {
		var zero T
		a.Items = append(a.Items, zero) // append one item, mostly enlarge cap by more than one item
	}

	_ = a.Items[i]                   // BCE
	copy(a.Items[i+1:], a.Items[i:]) // shift one slot right, starting at [i]
	a.Items[i] = item                // insert new item at [i]
}

// deleteItem removes the item at index i from the Items slice,
// shifting all subsequent items one position to the left,
// and clearing the final (now duplicate) slot.
//
// This is used to remove Items[i] in response to a BitSet256.Clear(i)
// operation, where i is guaranteed to be set and valid.
//
// Example (deleting rank0 == 1):
//
//	Items before: [A B C D]
//	After deleteItem(1): [A C D]
//
// The tail item is explicitly cleared (assigned the zero-value of T)
// to avoid holding references (important for GC with pointer types).
//
// Panics if i is out of range (i < 0 or i >= len(Items)).
func (a *Array256[T]) deleteItem(i int) {
	var zero T

	_ = a.Items[i]                   // BCE
	copy(a.Items[i:], a.Items[i+1:]) // shift left, overwrite item at [i]

	nl := len(a.Items) - 1 // new len

	a.Items[nl] = zero     // clear the tail item
	a.Items = a.Items[:nl] // new len, cap is unchanged
}
