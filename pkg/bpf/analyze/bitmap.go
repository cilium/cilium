// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"math/bits"
	"unsafe"
)

// Bitmap is a Bitmap used to track which blocks are reachable in the control
// flow graph.
type Bitmap []uint64

const wordSize = uint64(unsafe.Alignof(Bitmap(nil)[0]) * 8)

// NewBitmap returns a bitmap capable of tracking at least n items. All bits are
// false by default.
func NewBitmap(n uint64) Bitmap {
	return make(Bitmap, (n+(wordSize-1))/wordSize)
}

// Set sets the bit at index i to the given value. If i is out of bounds, it
// does nothing.
func (b Bitmap) Set(i uint64, value bool) {
	word, bit := i/wordSize, i%wordSize
	if word >= uint64(len(b)) {
		return
	}

	if value {
		b[word] |= 1 << (bit)
	} else {
		b[word] &^= 1 << (bit)
	}
}

// Get returns the value of the bit at index i. If i is out of bounds, it
// returns false.
func (b Bitmap) Get(i uint64) bool {
	word, bit := i/wordSize, i%wordSize
	if word >= uint64(len(b)) {
		return false
	}

	return b[word]&(1<<(bit)) != 0
}

// Popcount returns the number of bits set to true in the bitmap.
func (b Bitmap) Popcount() uint64 {
	var count int
	for _, w := range b {
		count += bits.OnesCount64(w)
	}
	return uint64(count)
}
