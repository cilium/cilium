// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"
)

func iterateAll(b *RingBuffer[int]) []int {
	acc := []int{}
	b.Iterate(func(n int) {
		acc = append(acc, n)
	})
	return acc
}

func TestRingBuffer_AddingAndIterating(t *testing.T) {
	assert := assert.New(t)
	bufferSize := 5
	buffer := NewRingBuffer[int](bufferSize)
	for i := 1; i <= 10; i++ {
		buffer.Add(i)
	}
	assert.Len(buffer.buffer, bufferSize)
	acc := iterateAll(buffer)
	assert.IsIncreasing(acc)
	assert.Equal([]int{6, 7, 8, 9, 10}, acc)

	buffer.Add(11)
	acc = iterateAll(buffer)
	assert.Equal([]int{7, 8, 9, 10, 11}, acc)

	d := []int{}
	buffer.Iterate(func(i int) {
		d = append(d, i)
	})
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
	acc := iterateAll(buffer)
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

	acc := []int{}
	buffer.IterateFrom(2, func(n int) { acc = append(acc, n) })
	assert.Equal([]int{5, 6, 7}, acc)

	acc = []int{}
	buffer.IterateFrom(0, func(n int) { acc = append(acc, n) })
	assert.Equal(iterateAll(buffer), acc)

	acc = []int{}
	buffer.IterateFrom(5, func(n int) { acc = append(acc, n) })
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
	assert.Equal([]int{3, 4}, iterateAll(buf))

	// Drain from a full buffer with a wrapped head.
	buf = NewRingBuffer[int](4)
	for i := 1; i <= 6; i++ {
		buf.Add(i) // [5,6,3,4] next=2 → logical [3,4,5,6]
	}
	buf.Drain(1)
	assert.Equal([]int{4, 5, 6}, iterateAll(buf))

	// Drain all elements.
	buf = NewRingBuffer[int](4)
	for i := 1; i <= 4; i++ {
		buf.Add(i)
	}
	buf.Drain(4)
	assert.Equal(0, buf.Size())
	assert.Empty(iterateAll(buf))

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
	assert.Equal([]int{1, 2, 3}, iterateAll(buf))

	// Buffer remains usable after Drain.
	buf = NewRingBuffer[int](4)
	for i := 1; i <= 4; i++ {
		buf.Add(i)
	}
	buf.Drain(2)
	buf.Add(5)
	buf.Add(6)
	assert.Equal([]int{3, 4, 5, 6}, iterateAll(buf))
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
		all := iterateAll(buf)
		n := rand.IntN(len(all) + 1)
		buf.Drain(n)
		assert.Equal(all[n:], iterateAll(buf))
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
		all := iterateAll(buffer)
		for i, v := range all {
			assert.Equal(v, buffer.At(i))
		}
		if len(all) > 0 {
			start := rand.IntN(len(all))
			acc := []int{}
			buffer.IterateFrom(start, func(n int) { acc = append(acc, n) })
			assert.Equal(all[start:], acc)
		}
	}
}
