// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"sort"
)

// OrderedRingBuffer extends the RingBuffer for use with monotonically ordered data
// (e.g. time-ordered events).
//
// Relying on data that has some monotonically increasing property, such as
// timestamps, OrderedRingBuffer allows for iteration and compaction (i.e.
// removal) of expired or invalid entries.
type OrderedRingBuffer[T any] struct {
	*RingBuffer[T]
}

// NewOrderedRingBuffer constructs a new OrderedRingBuffer with the given capacity.
func NewOrderedRingBuffer[T any](bufferSize int) *OrderedRingBuffer[T] {
	return &OrderedRingBuffer[T]{NewRingBuffer[T](bufferSize)}
}

// firstValidIndex returns the first logical index i such that isValid(At(i)) is
// true.
// The isValid must be a monotone property of the underlying type T such that
// some, possibly empty, prefix of elements is not valid and the remaining elements
// are all *only* valid.
func (o *OrderedRingBuffer[T]) firstValidIndex(isValid func(T) bool) int {
	return sort.Search(o.Size(), func(i int) bool {
		return isValid(o.At(i))
	})
}

// IterateValid calls callback on each element starting from the first element
// that satisfies isValid. isValid must be monotone (false-then-true) over the
// insertion-ordered sequence.
func (o *OrderedRingBuffer[T]) IterateValid(isValid func(T) bool, callback func(T)) {
	o.IterateFrom(o.firstValidIndex(isValid), callback)
}

// Compact removes the invalid prefix from the buffer. It is assumed that if
// element i is invalid then all elements [0..i-1] are also invalid (i.e. the
// predicate is monotone). This may require copying the entire buffer.
func (o *OrderedRingBuffer[T]) Compact(isValid func(T) bool) {
	o.Drain(o.firstValidIndex(isValid))
}
