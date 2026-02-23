// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cookie

import (
	"math/big"
	"math/rand/v2"
)

// bitset is an uncompressed bitset/bitmap.
type bitset struct {
	// length is the maximum length.
	length int
	// count is the number of allocated bits.
	count int
	// set stores allocated bits.
	set *big.Int
}

// newBitset allocates a new bitset holding a maximum of length bits.
func newBitset(length int) *bitset {
	return &bitset{
		length: length,
		count:  0,
		set:    big.NewInt(0),
	}
}

// Allocates a bit at the next free offset, starting at 0 and filling any gaps. It also returns
// whether a bit could be allocated.
//
// By allocating sequentially and filling gaps we save memory compared to a random strategy which in
// the worst case would allocate the bit at 2^32-1 in a big.Int on first allocation.
//
// We expect a sparse set of allocated bits, thus a random allocation strategy is not suitable.
//
// TODO: if this assumption changes, consider using a compressed bitset such as Roaring bitmaps.
func (b *bitset) Allocate() (int, bool) {
	if b.count >= b.length {
		return 0, false
	}
	for next := range b.length {
		if b.set.Bit(next) == 0 {
			b.set = b.set.SetBit(b.set, next, 1)
			b.count++
			return next, true
		}
	}
	return 0, false
}

// Allocates a bit at a random free offset. It also returns whether a bit could be allocated.
func (b *bitset) AllocateRand() (int, bool) {
	if b.count >= b.length {
		return 0, false
	}
	off := rand.IntN(b.length)
	for i := range b.length {
		next := (off + i) % b.length
		if b.set.Bit(next) == 0 {
			b.set = b.set.SetBit(b.set, next, 1)
			b.count++
			return next, true
		}
	}
	return 0, false
}

// Release releases the bit at offset.
func (b *bitset) Release(offset int) {
	if b.set.Bit(offset) == 0 {
		return
	}
	b.set = b.set.SetBit(b.set, offset, 0)
	b.count--
}

// Count returns the number of set bits.
func (b *bitset) Count() int {
	return b.count
}

// Cap returns the number of unset bits, the remaining capacity of the bit set.
func (b *bitset) Cap() int {
	return b.length - b.count
}
