// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func collectAll(b *RingBuffer[int]) []int {
	out := slices.Collect(b.Iterate())
	if out == nil {
		return []int{}
	}
	return out
}

func TestRingBuffer_AddingAndIterating(t *testing.T) {
	assert := assert.New(t)
	bufferSize := 5
	buffer := NewRingBuffer[int](bufferSize)
	for i := 1; i <= 10; i++ {
		buffer.Add(i)
	}
	assert.Len(buffer.buffer, bufferSize)
	acc := collectAll(buffer)
	assert.IsIncreasing(acc)
	assert.Equal([]int{6, 7, 8, 9, 10}, acc)

	buffer.Add(11)
	acc = collectAll(buffer)
	assert.Equal([]int{7, 8, 9, 10, 11}, acc)

	d := collectAll(buffer)
	assert.IsNonDecreasing(d)
	assert.Equal([]int{7, 8, 9, 10, 11}, d)

	buffer = NewRingBuffer[int](0)
	assert.Empty(buffer.buffer)
	buffer.Add(123)
	assert.Empty(buffer.buffer)
}

func TestRingBuffer_At(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer[int](5)
	for i := 1; i <= 7; i++ {
		buffer.Add(i)
	}
	acc := collectAll(buffer)
	for i, v := range acc {
		assert.Equal(v, buffer.At(i))
	}
}

func TestRingBuffer_IterateFrom(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer[int](5)
	for i := 1; i <= 7; i++ {
		buffer.Add(i)
	}

	acc := slices.Collect(buffer.IterateFrom(2))
	assert.Equal([]int{5, 6, 7}, acc)

	acc = slices.Collect(buffer.IterateFrom(0))
	assert.Equal(collectAll(buffer), acc)

	acc = slices.Collect(buffer.IterateFrom(5))
	assert.Empty(acc)
}

func TestRingBuffer_Drain(t *testing.T) {
	assert := assert.New(t)

	// Drain from a non-wrapping buffer.
	buf := NewRingBuffer[int](5)
	for i := 1; i <= 4; i++ {
		buf.Add(i)
	}
	buf.Drain(2)
	assert.Equal([]int{3, 4}, collectAll(buf))

	// Drain from a full buffer with a wrapped head.
	buf = NewRingBuffer[int](4)
	for i := 1; i <= 6; i++ {
		buf.Add(i) // [5,6,3,4] next=2 → logical [3,4,5,6]
	}
	buf.Drain(1)
	assert.Equal([]int{4, 5, 6}, collectAll(buf))

	// Drain all elements.
	buf = NewRingBuffer[int](4)
	for i := 1; i <= 4; i++ {
		buf.Add(i)
	}
	buf.Drain(4)
	assert.Equal(0, buf.Size())
	assert.Empty(collectAll(buf))

	// Drain more than Size clears the buffer.
	buf = NewRingBuffer[int](4)
	buf.Add(1)
	buf.Drain(10)
	assert.Equal(0, buf.Size())

	// Drain(0) is a no-op.
	buf = NewRingBuffer[int](4)
	for i := 1; i <= 3; i++ {
		buf.Add(i)
	}
	buf.Drain(0)
	assert.Equal([]int{1, 2, 3}, collectAll(buf))

	// Buffer remains usable after Drain.
	buf = NewRingBuffer[int](4)
	for i := 1; i <= 4; i++ {
		buf.Add(i)
	}
	buf.Drain(2)
	buf.Add(5)
	buf.Add(6)
	assert.Equal([]int{3, 4, 5, 6}, collectAll(buf))
}

func TestRingBuffer_Drain_Randomized(t *testing.T) {
	assert := assert.New(t)
	for range 1000 {
		size := rand.IntN(10) + 1
		adds := rand.IntN(size * 2)
		buf := NewRingBuffer[int](size)
		for i := range adds {
			buf.Add(i)
		}
		all := collectAll(buf)
		n := rand.IntN(len(all) + 1)
		buf.Drain(n)
		assert.Equal(all[n:], collectAll(buf))
	}
}

func TestRingBuffer_AtIterateFrom_Randomized(t *testing.T) {
	assert := assert.New(t)
	for range 1000 {
		size := rand.IntN(20) + 1
		adds := rand.IntN(size * 2)
		buffer := NewRingBuffer[int](size)
		for i := range adds {
			buffer.Add(i)
		}
		all := collectAll(buffer)
		for i, v := range all {
			assert.Equal(v, buffer.At(i))
		}
		if len(all) > 0 {
			start := rand.IntN(len(all))
			acc := []int{}
			for n := range buffer.IterateFrom(start) {
				acc = append(acc, n)
			}
			assert.Equal(all[start:], acc)
		}
	}
}
