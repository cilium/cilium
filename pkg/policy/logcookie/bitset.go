// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logcookie

import (
	"math/big"
	"math/rand/v2"
)

// bitset
// TODO: consider using bitmap compression, i.e. Roaring bitmap.
type bitset struct {
	// length is the maximum length.
	length uint
	// count is the number of allocated bits.
	count uint
	// set stores allocated bits.
	set *big.Int
}

func newBitset(length uint) *bitset {
	return &bitset{
		length: length,
		count:  0,
		set:    big.NewInt(0),
	}
}

// Allocates a previously free bit at a random offset. It also returns whether a bit could be
// allocated.
func (b *bitset) Allocate() (uint, bool) {
	if b.count >= b.length {
		return 0, false
	}
	off := rand.UintN(b.length)
	for i := range b.length {
		next := (off + i) % b.length
		if b.set.Bit(int(next)) == 0 {
			b.set = b.set.SetBit(b.set, int(next), 1)
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
func (b *bitset) Count() uint {
	return b.count
}

// Cap returns the number of unset bits, the remaining capacity of the bit set.
func (b *bitset) Cap() uint {
	return b.length - b.count
}
