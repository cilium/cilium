// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cookie

import (
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitset(t *testing.T) {
	length := 128

	b := newBitset(length)

	assert.Equal(t, 0, b.Count())
	assert.Equal(t, length, b.Cap())

	b.Release(0)
	assert.Equal(t, 0, b.Count())
	assert.Equal(t, length, b.Cap())

	seenBits := make(map[int]struct{})

	lastBit, ok := b.Allocate()
	assert.True(t, ok)
	assert.Equal(t, 1, b.Count())
	assert.Equal(t, length-1, b.Cap())
	seenBits[lastBit] = struct{}{}

	for i := range length - 2 {
		bit, ok := b.Allocate()
		assert.True(t, ok)
		// Allocate allocates sequentially
		assert.Equal(t, bit, lastBit+1)
		assert.Equal(t, b.Count(), i+1+1)
		assert.Equal(t, b.Cap(), length-1-i-1)

		_, seen := seenBits[bit]
		assert.False(t, seen, "seen bit %d more than once", bit)
		seenBits[bit] = struct{}{}

		lastBit = bit
	}

	bit, ok := b.AllocateRand()
	assert.True(t, ok)
	assert.Equal(t, length, b.Count())
	assert.Equal(t, 0, b.Cap())

	_, seen := seenBits[bit]
	assert.False(t, seen, "seen bit %d more than once", bit)
	seenBits[bit] = struct{}{}

	// Bit set full
	bit, ok = b.Allocate()
	assert.False(t, ok)
	assert.Zero(t, bit)
	assert.Equal(t, length, b.Count())
	assert.Equal(t, 0, b.Cap())

	bit, ok = b.AllocateRand()
	assert.False(t, ok)
	assert.Zero(t, bit)
	assert.Equal(t, length, b.Count())
	assert.Equal(t, 0, b.Cap())

	// Free bit at random offset
	off := rand.IntN(length)
	b.Release(off)
	assert.Equal(t, length-1, b.Count())
	assert.Equal(t, 1, b.Cap())

	// Allocate should allocate the only free bit
	bit, ok = b.Allocate()
	assert.True(t, ok)
	assert.Equal(t, bit, off)
	assert.Equal(t, length, b.Count())
	assert.Equal(t, 0, b.Cap())

	// Free bit at random offset
	off = rand.IntN(length)
	b.Release(off)
	assert.Equal(t, length-1, b.Count())
	assert.Equal(t, 1, b.Cap())
	// Releasing twice shouldn't change anything
	b.Release(off)
	assert.Equal(t, length-1, b.Count())
	assert.Equal(t, 1, b.Cap())

	// AllocateRand should allocate the only free bit
	bit, ok = b.AllocateRand()
	assert.True(t, ok)
	assert.Equal(t, off, bit)
	assert.Equal(t, length, b.Count())
	assert.Equal(t, 0, b.Cap())

	for i := range length {
		b.Release(i)
		assert.Equal(t, b.Count(), length-i-1)
		assert.Equal(t, b.Cap(), i+1)
	}
}
