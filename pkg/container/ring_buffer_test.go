// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func dumpBuffer(b *RingBuffer) []int {
	acc := []int{}
	b.dumpWithCallback(func(n interface{}) {
		acc = append(acc, n.(int))
	})
	return acc
}

func dumpFunc(b *RingBuffer) func() []int {
	return func() []int {
		acc := []int{}
		b.Iterate(func(i interface{}) {
			acc = append(acc, i.(int))
		})
		return acc
	}
}

func TestRingBuffer_AddingAndIterating(t *testing.T) {
	assert := assert.New(t)
	bufferSize := 5
	buffer := NewRingBuffer(bufferSize)
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
	buffer.Iterate(func(i interface{}) {
		d = append(d, i.(int))
	})
	assert.IsNonDecreasing(d)
	assert.Equal([]int{7, 8, 9, 10, 11}, d)
	acc = []int{}
	buffer.IterateValid(func(n interface{}) bool {
		return n.(int) >= 9
	}, func(n interface{}) {
		acc = append(acc, n.(int))
	})
	assert.Equal([]int{9, 10, 11}, acc)

	acc = []int{}
	buffer.IterateValid(func(n interface{}) bool {
		return n.(int) >= 0
	}, func(n interface{}) {
		acc = append(acc, n.(int))
	})
	assert.Equal([]int{7, 8, 9, 10, 11}, acc)

	acc = []int{}
	buffer.IterateValid(func(n interface{}) bool {
		return n.(int) >= 11
	}, func(n interface{}) {
		acc = append(acc, n.(int))
	})
	assert.Equal([]int{11}, acc)

	acc = []int{}
	buffer.IterateValid(func(n interface{}) bool {
		return n.(int) > 11
	}, func(n interface{}) {
		acc = append(acc, n.(int))
	})
	assert.Empty(acc)

	// Test empty buffer.
	buffer = NewRingBuffer(0)
	acc = dumpBuffer(buffer)
	assert.Empty(acc)
	assert.Empty(buffer.buffer)
	buffer.Add(123)
	assert.Empty(buffer.buffer)

}

func TestEventBuffer_GC(t *testing.T) {
	assert := assert.New(t)
	for i := 0; i < 3; i++ {
		buffer := NewRingBuffer(100)
		for i := 1; i <= 102; i++ {
			buffer.Add(i)
		}
		buffer.Compact(func(n interface{}) bool {
			return n.(int) > 95
		})
		df := dumpFunc(buffer)
		assert.Equal([]int{96, 97, 98, 99, 100, 101, 102}, df())

		buffer.Compact(func(n interface{}) bool { return true })
		assert.Equal(7, buffer.Size(), "always valid shouldn't clear anything")
		buffer.Compact(func(n interface{}) bool { return false })
		assert.Equal(0, buffer.Size(), "nothing valid should empty buffer")
		buffer.Compact(func(n interface{}) bool { return true })
		assert.Equal(0, buffer.Size(), "test gc empty buffer")
	}
}

func TestEventBuffer_GC2(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer(3)
	df := dumpFunc(buffer)
	buffer.buffer = []interface{}{3, 1, 2}
	buffer.next = 1
	buffer.Compact(func(n interface{}) bool {
		return n.(int) >= 2
	})
	assert.Equal([]int{2, 3}, df())
	buffer.Compact(func(n interface{}) bool {
		return n.(int) >= 2 // noop
	})
	assert.Equal([]int{2, 3}, df())
	buffer.Compact(func(n interface{}) bool {
		return n.(int) >= 3
	})
	assert.Equal([]int{3}, df())
}

func TestEventBuffer_GCFullBufferWithOverlap(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer(5)
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
	assert.Equal([]interface{}{6, 7, 3, 4, 5}, buffer.buffer)
	assert.Equal(2, buffer.next)
	buffer.Compact(func(n interface{}) bool {
		return n.(int) >= 5 // -> 5, 6, 7
	})
	acc := dumpBuffer(buffer)
	assert.Equal([]int{5, 6, 7}, acc)
}

func TestEventBuffer_GCFullBuffer(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer(5)
	buffer.Add(1)
	buffer.Add(2)
	buffer.Add(3)
	buffer.Add(4)
	buffer.Add(5)
	assert.Equal([]interface{}{1, 2, 3, 4, 5}, buffer.buffer)
	assert.True(buffer.isFull())
	buffer.Compact(func(n interface{}) bool {
		return n.(int) >= 2
	})
	assert.Equal([]interface{}{2, 3, 4, 5}, buffer.buffer)
}

func TestEventBuffer_GCNotFullBuffer(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer(5)
	buffer.Add(1)
	buffer.Add(2)
	buffer.Add(3)
	buffer.Add(4)
	assert.Equal([]interface{}{1, 2, 3, 4}, buffer.buffer)
	assert.False(buffer.isFull())
	i := buffer.firstValidIndex(func(n interface{}) bool {
		return n.(int) > 3
	})
	assert.Equal(3, i)
	i = buffer.firstValidIndex(func(n interface{}) bool {
		return n.(int) > 4
	})
	assert.Equal(4, i, "should be out of bounds")
	buffer.Compact(func(n interface{}) bool {
		return n.(int) > 4
	})
	assert.Equal([]interface{}{}, buffer.buffer)
	buffer.Add(1)
	buffer.Add(1)
	buffer.Add(1)
	buffer.Add(1)
	buffer.Add(1)
	i = buffer.firstValidIndex(func(n interface{}) bool {
		return n.(int) >= 1
	})
	assert.Equal(0, i)
	buffer.Compact(func(n interface{}) bool {
		return n.(int) > 0
	})
	assert.Equal([]interface{}{1, 1, 1, 1, 1}, buffer.buffer)
	buffer.Compact(func(n interface{}) bool {
		return false
	})
	assert.Empty(buffer.buffer)
}

func Test_firstValidIndex(t *testing.T) {
	assert := assert.New(t)
	buffer := NewRingBuffer(4)
	df := dumpFunc(buffer)
	for i := 0; i < 5; i++ {
		buffer.Add(i)
	}
	assert.IsNonDecreasing(df())
	for i := 1; i <= 4; i++ {
		assert.Equal(i, buffer.firstValidIndex(func(ii interface{}) bool {
			return ii.(int) > i
		}))
	}
	assert.Equal(4, buffer.firstValidIndex(func(ii interface{}) bool { return ii.(int) > 4 }))
	assert.Equal(4, buffer.firstValidIndex(func(ii interface{}) bool { return false }))
	assert.Equal(0, buffer.firstValidIndex(func(ii interface{}) bool { return true }))
}

func Test_firstValidIndex2(t *testing.T) {
	assert := assert.New(t)
	for i := 0; i <= 1000; i++ {
		s := rand.Intn(1000)
		buffer := NewRingBuffer(s)
		df := dumpFunc(buffer)
		for i := 0; i < s+1; i++ {
			buffer.Add(i)
		}
		assert.IsNonDecreasing(df())
		for i := 1; i <= s; i++ {
			assert.Equal(i, buffer.firstValidIndex(func(ii interface{}) bool {
				return ii.(int) > i
			}))
		}
		assert.Equal(s, buffer.firstValidIndex(func(ii interface{}) bool { return ii.(int) > s }))
		assert.Equal(s, buffer.firstValidIndex(func(ii interface{}) bool { return false }))
		assert.Equal(0, buffer.firstValidIndex(func(ii interface{}) bool { return true }))
	}
}
