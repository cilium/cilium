// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"unsafe"
)

// bitmap is a bitmap used to track which blocks are reachable in the control
// flow graph.
type bitmap []uint64

const wordSize = uint64(unsafe.Alignof(bitmap(nil)[0]) * 8)

// newBitmap returns a bitmap capable of tracking at least n items. All bits are
// false by default.
func newBitmap(n uint64) bitmap {
	return make(bitmap, (n+(wordSize-1))/wordSize)
}

// set sets the bit at index i to the given value. If i is out of bounds, it
// does nothing.
func (b bitmap) set(i uint64, value bool) {
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

// get returns the value of the bit at index i. If i is out of bounds, it
// returns false.
func (b bitmap) get(i uint64) bool {
	word, bit := i/wordSize, i%wordSize
	if word >= uint64(len(b)) {
		return false
	}

	return b[word]&(1<<(bit)) != 0
}
