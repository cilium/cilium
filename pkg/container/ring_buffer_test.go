// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"
)

func dumpBuffer(b *RingBuffer[int]) []int {
	acc := []int{}
	b.dumpWithCallback(func(n int) {
		acc = append(acc, n)
	})
	return acc
}

func dumpFunc(b *RingBuffer[int]) func() []int {
	return func() []int {
		acc := []int{}
		b.Iterate(func(i int) {
			acc = append(acc, i)
		})
		return acc
	}
}

func TestRingBuffer_AddingAndIterating(t *testing.T) {
	assert := assert.New(t)
	bufferSize := 5
	buffer := NewRingBuffer[int](bufferSize)
	dumpAll := dumpFunc(buffer)
	for i := 1; i <= 10; i++ {
		buffer.Add(i)
	}
	assert.Len(buffer.buffer, bufferSize)
	acc := dumpAll()
	assert.IsIncreasing(acc)
	assert.Equal([]int{6, 7, 8, 9, 10}, acc)

	buffer.Add(11)
	acc = dumpAll()
	assert.Equal([]int{7, 8, 9, 10, 11}, acc)

	d := []int{}
	buffer.Iterate(func(i int) {
		d = append(d, i)
	})
	assert.IsNonDecreasing(d)
	assert.Equal([]int{7, 8, 9, 10, 11}, d)
	acc = []int{}
	buffer.IterateValid(func(n int) bool {
		return n >= 9
	}, func(n int) {
		acc = append(acc, n)
	})
	assert.Equal([]int{9, 10, 11}, acc)

	acc = []int{}
	buffer.IterateValid(func(n int) bool {
		return n >= 0
	}, func(n int) {
		acc = append(acc, n)
	})
	assert.Equal([]int{7, 8, 9, 10, 11}, acc)

	acc = []int{}
	buffer.IterateValid(func(n int) bool {
		return n >= 11
	}, func(n int) {
		acc = append(acc, n)
	})
	assert.Equal([]int{11}, acc)

	acc = []int{}
	buffer.IterateValid(func(n int) bool {
		return n > 11
	}, func(n int) {
		acc = append(acc, n)
	})
	assert.Empty(acc)

	// Test empty buffer.
	buffer = NewRingBuffer[int](0)
	acc = dumpBuffer(buffer)
	assert.Empty(acc)
	assert.Empty(buffer.buffer)
	buffer.Add(123)
	assert.Empty(buffer.buffer)

}

func TestEventBuffer_GC(t *testing.T) {
	assert := assert.New(t)
	for range 3 {
		buffer := NewRingBuffer[int](100)
		for i := 1; i <= 102; i++ {
			buffer.Add(i)
		}
		buffer.Compact(func(n int) bool {
			return n > 95
		})
		df := dumpFunc(buffer)
		assert.Equal([]int{96, 97, 98, 99, 100, 101, 102}, df())

		buffer.Compact(func(n int) bool { return true })
		assert.Equal(7, buffer.Size(), "always valid shouldn't clear anything")
		buffer.Compact(func(n int) bool { return false })
		assert.Equal(0, buffer.Size(), "nothing valid should empty buffer")
		buffer.Compact(func(n int) bool { return true })
		assert.Equal(0, buffer.Size(), "test gc empty buffer")
	}
}

func TestEventBuffer_GC2(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer[int](3)
	df := dumpFunc(buffer)
	buffer.buffer = []int{3, 1, 2}
	buffer.next = 1
	buffer.Compact(func(n int) bool {
		return n >= 2
	})
	assert.Equal([]int{2, 3}, df())
	buffer.Compact(func(n int) bool {
		return n >= 2 // noop
	})
	assert.Equal([]int{2, 3}, df())
	buffer.Compact(func(n int) bool {
		return n >= 3
	})
	assert.Equal([]int{3}, df())
}

func TestEventBuffer_GCFullBufferWithOverlap(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer[int](5)
	buffer.Add(1)
	buffer.Add(2)
	buffer.Add(3)
	buffer.Add(4)
	buffer.Add(5)
	buffer.Add(6)
	buffer.Add(7)
	df := dumpFunc(buffer)
	assert.Equal([]int{3, 4, 5, 6, 7}, df())
	assert.True(buffer.isFull(), "this is a full buffer, which has gone around past its tail")
	assert.Equal([]int{6, 7, 3, 4, 5}, buffer.buffer)
	assert.Equal(2, buffer.next)
	buffer.Compact(func(n int) bool {
		return n >= 5 // -> 5, 6, 7
	})
	acc := dumpBuffer(buffer)
	assert.Equal([]int{5, 6, 7}, acc)
}

func TestEventBuffer_GCFullBuffer(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer[int](5)
	buffer.Add(1)
	buffer.Add(2)
	buffer.Add(3)
	buffer.Add(4)
	buffer.Add(5)
	assert.Equal([]int{1, 2, 3, 4, 5}, buffer.buffer)
	assert.True(buffer.isFull())
	buffer.Compact(func(n int) bool {
		return n >= 2
	})
	assert.Equal([]int{2, 3, 4, 5}, buffer.buffer)
}

func TestEventBuffer_GCNotFullBuffer(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer[int](5)
	buffer.Add(1)
	buffer.Add(2)
	buffer.Add(3)
	buffer.Add(4)
	assert.Equal([]int{1, 2, 3, 4}, buffer.buffer)
	assert.False(buffer.isFull())
	i := buffer.firstValidIndex(func(n int) bool {
		return n > 3
	})
	assert.Equal(3, i)
	i = buffer.firstValidIndex(func(n int) bool {
		return n > 4
	})
	assert.Equal(4, i, "should be out of bounds")
	buffer.Compact(func(n int) bool {
		return n > 4
	})
	assert.Equal([]int{}, buffer.buffer)
	buffer.Add(1)
	buffer.Add(1)
	buffer.Add(1)
	buffer.Add(1)
	buffer.Add(1)
	i = buffer.firstValidIndex(func(n int) bool {
		return n >= 1
	})
	assert.Equal(0, i)
	buffer.Compact(func(n int) bool {
		return n > 0
	})
	assert.Equal([]int{1, 1, 1, 1, 1}, buffer.buffer)
	buffer.Compact(func(n int) bool {
		return false
	})
	assert.Empty(buffer.buffer)
}

func Test_firstValidIndex(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer[int](4)
	df := dumpFunc(buffer)
	for i := range 5 {
		buffer.Add(i)
	}
	assert.IsNonDecreasing(df())
	for i := 1; i <= 4; i++ {
		assert.Equal(i, buffer.firstValidIndex(func(ii int) bool {
			return ii > i
		}))
	}
	assert.Equal(4, buffer.firstValidIndex(func(ii int) bool { return ii > 4 }))
	assert.Equal(4, buffer.firstValidIndex(func(ii int) bool { return false }))
	assert.Equal(0, buffer.firstValidIndex(func(ii int) bool { return true }))
}

func Test_firstValidIndex2(t *testing.T) {
	assert := assert.New(t)
	for i := 0; i <= 1000; i++ {
		s := rand.IntN(1000)
		buffer := NewRingBuffer[int](s)
		df := dumpFunc(buffer)
		for i := range s + 1 {
			buffer.Add(i)
		}
		assert.IsNonDecreasing(df())
		for i := 1; i <= s; i++ {
			assert.Equal(i, buffer.firstValidIndex(func(ii int) bool {
				return ii > i
			}))
		}
		assert.Equal(s, buffer.firstValidIndex(func(ii int) bool { return ii > s }))
		assert.Equal(s, buffer.firstValidIndex(func(ii int) bool { return false }))
		assert.Equal(0, buffer.firstValidIndex(func(ii int) bool { return true }))
	}
}
