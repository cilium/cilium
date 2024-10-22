// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"sort"
)

// RingBuffer is a generic ring buffer implementation that contains
// sequential data (i.e. such as time ordered data).
// RingBuffer is implemented using slices. From testing, this should
// be fast than linked-list implementations, and also allows for efficient
// indexing of ordered data.
type RingBuffer struct {
	buffer  []interface{}
	next    int // index of ring buffer head.
	maxSize int
}

// NewRingBuffer constructs a new ring buffer for a given buffer size.
func NewRingBuffer(bufferSize int) *RingBuffer {
	return &RingBuffer{
		buffer:  make([]interface{}, 0, bufferSize),
		maxSize: bufferSize,
	}
}

func (eb *RingBuffer) isFull() bool {
	return len(eb.buffer) >= eb.maxSize
}

func (eb *RingBuffer) incr() {
	eb.next = (eb.next + 1) % eb.maxSize
}

// Add adds an element to the buffer.
func (eb *RingBuffer) Add(e interface{}) {
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

func (eb *RingBuffer) dumpWithCallback(callback func(v interface{})) {
	for i := 0; i < len(eb.buffer); i++ {
		callback(eb.at(i))
	}
}

func (eb *RingBuffer) at(i int) interface{} {
	return eb.buffer[eb.mapIndex(i)]
}

// firstValidIndex returns the first **absolute** index in the buffer that satisfies
// isValid.
// note: this value needs to be mapped before indexing the buffer.
func (eb *RingBuffer) firstValidIndex(isValid func(interface{}) bool) int {
	return sort.Search(len(eb.buffer), func(i int) bool {
		return isValid(eb.at(i))
	})
}

// IterateValid calls the callback on each element of the buffer, starting with
// the first element in the buffer that satisfies "isValid".
func (eb *RingBuffer) IterateValid(isValid func(interface{}) bool, callback func(interface{})) {
	startIndex := eb.firstValidIndex(isValid)
	l := len(eb.buffer) - startIndex
	for i := 0; i < l; i++ {
		index := eb.mapIndex(startIndex + i)
		callback(eb.buffer[index])
	}
}

// maps index in [0:len(buffer)) to the actual index in buffer.
func (eb *RingBuffer) mapIndex(indexOffset int) int {
	ret := (eb.next + indexOffset) % len(eb.buffer)
	return ret
}

// Compact clears out invalidated elements in the buffer.
// This may require copying the entire buffer.
// It is assumed that if buffer[i] is invalid then every entry [0...i-1] is also not valid.
func (eb *RingBuffer) Compact(isValid func(interface{}) bool) {
	if len(eb.buffer) == 0 {
		return
	}
	startIndex := eb.firstValidIndex(isValid)
	// In this case, we compact the entire buffer.
	if startIndex >= len(eb.buffer) {
		eb.buffer = []interface{}{}
		eb.next = 0
		return
	}

	mappedStart := eb.mapIndex(startIndex) // mapped start is the new index 0 of our buffer.
	// new length will be how long the current buffer is, minus the absolute starting index.
	newBufferLength := len(eb.buffer) - startIndex
	// case where the head index is to the left of the tail index.
	// e.x. [... head, tail, ...]
	// mappedStart + newBufferLength is the upper bound of the new buffer list
	// if we don't have to worry about mapping.
	//
	// e.x. [mappedStart:mappedStart+newBufferLength] <- this is our new buffer.
	//
	// If this value is less than or equal to the length then we don't need
	// to worry about any part of the list wrapping around.
	if mappedStart+newBufferLength > len(eb.buffer) {
		// now we can find the actual end index, by offsetting the startIndex
		// by the length and mapping it.
		// [... startIndex+newBufferLen ... startIndex ...]
		end := eb.mapIndex(startIndex + newBufferLength)
		tmp := make([]interface{}, len(eb.buffer[:end]))
		copy(tmp, eb.buffer[:end])

		eb.buffer = eb.buffer[mappedStart:]
		eb.buffer = append(eb.buffer, tmp...)

		// at this point the buffer is such that the 0th element
		// maps to the 0th index in the buffer array.
		eb.next = len(eb.buffer)
		if eb.isFull() {
			eb.next = eb.next % eb.maxSize
		}
		return
	}
	// otherwise, the head is to the right of the tail.
	begin := mappedStart
	end := mappedStart + newBufferLength
	eb.buffer = eb.buffer[begin:end]
	eb.next = len(eb.buffer)
	if eb.isFull() {
		eb.next = eb.next % eb.maxSize
	}
}

// Iterate is a convenience function over IterateValid that iterates
// all elements in the buffer.
func (eb *RingBuffer) Iterate(callback func(interface{})) {
	eb.IterateValid(func(e interface{}) bool { return true }, callback)
}

// Size returns the size of the buffer.
func (eb *RingBuffer) Size() int {
	return len(eb.buffer)
}
