// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

// RingBuffer is a generic ring buffer implementation.
// RingBuffer is implemented using slices. From testing, this should
// be faster than linked-list implementations, and also allows for efficient
// random access of ordered data.
type RingBuffer[T any] struct {
	buffer  []T
	next    int // index of ring buffer head.
	maxSize int
}

// NewRingBuffer constructs a new ring buffer for a given buffer size.
func NewRingBuffer[T any](bufferSize int) *RingBuffer[T] {
	return &RingBuffer[T]{
		buffer:  make([]T, 0, bufferSize),
		maxSize: bufferSize,
	}
}

func (eb *RingBuffer[T]) isFull() bool {
	return len(eb.buffer) >= eb.maxSize
}

func (eb *RingBuffer[T]) incr() {
	eb.next = (eb.next + 1) % eb.maxSize
}

// Add adds an element to the buffer.
func (eb *RingBuffer[T]) Add(e T) {
	if eb.maxSize == 0 {
		return
	}
	if eb.isFull() {
		eb.buffer[eb.next] = e
		eb.incr()
		return
	}
	eb.incr()
	eb.buffer = append(eb.buffer, e)
}

// At returns the element at logical index i, where 0 is the oldest element.
func (eb *RingBuffer[T]) At(i int) T {
	return eb.buffer[eb.mapIndex(i)]
}

// IterateFrom calls callback on each element starting at logical index startIdx.
func (eb *RingBuffer[T]) IterateFrom(startIdx int, callback func(T)) {
	for i := startIdx; i < len(eb.buffer); i++ {
		callback(eb.buffer[eb.mapIndex(i)])
	}
}

// Iterate calls callback on each element in insertion order.
func (eb *RingBuffer[T]) Iterate(callback func(T)) {
	eb.IterateFrom(0, callback)
}

// maps index in [0:len(buffer)) to the actual index in buffer.
func (eb *RingBuffer[T]) mapIndex(indexOffset int) int {
	return (eb.next + indexOffset) % len(eb.buffer)
}

// Size returns the number of elements in the buffer.
func (eb *RingBuffer[T]) Size() int {
	return len(eb.buffer)
}

// Drain removes the first n oldest elements from the buffer.
// If n >= Size(), the buffer is cleared.
func (eb *RingBuffer[T]) Drain(n int) {
	if n <= 0 {
		return
	}
	if n >= eb.Size() {
		eb.buffer = []T{}
		eb.next = 0
		return
	}
	mappedStart := eb.mapIndex(n)
	newLen := eb.Size() - n
	if mappedStart+newLen > len(eb.buffer) {
		// Retained segment wraps: [mappedStart:] ++ [:next]
		tmp := make([]T, eb.next)
		copy(tmp, eb.buffer[:eb.next])
		eb.buffer = append(eb.buffer[mappedStart:], tmp...)
	} else {
		eb.buffer = eb.buffer[mappedStart : mappedStart+newLen]
	}
	eb.next = len(eb.buffer)
	if eb.isFull() {
		eb.next = eb.next % eb.maxSize
	}
}
