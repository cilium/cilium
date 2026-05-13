// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

// Package bitset provides a compact and efficient implementation of a fixed-length
// bitset for the range [0..255].
//
// This implementation is optimized for internal use in a compressed routing trie
// and prioritizes minimal allocation, performance, and inlining. It supports
// constant-time set/test operations, iteration over set bits, ranking, and masked
// intersections.
//
// Internally, the bitset is represented by four uint64 words, providing
// fast bit-level access through direct indexing and hardware-accelerated primitives.
//
// If Go eventually supports SIMD intrinsics, this can be further optimized.
//
// For external consumers, the API intentionally avoids dynamic allocation except
// when explicitly requested (via Bits()).
package bitset

// can inline (*BitSet256).AsSlice with cost 42
// can inline (*BitSet256).Bits with cost 47
// can inline (*BitSet256).Clear with cost 12
// can inline (*BitSet256).FirstSet with cost 79
// can inline (*BitSet256).Intersects with cost 48
// can inline (*BitSet256).Intersection with cost 53
// can inline (*BitSet256).IntersectionTop with cost 42
// can inline (*BitSet256).IsEmpty with cost 22
// can inline (*BitSet256).LastSet with cost 37
// can inline (*BitSet256).NextSet with cost 65
// can inline (*BitSet256).Rank with cost 57
// can inline (*BitSet256).Set with cost 12
// can inline (*BitSet256).Size with cost 33
// can inline (*BitSet256).Test with cost 15
// can inline (*BitSet256).Union with cost 36

import (
	"math/bits"
)

//   wordIdx calculates the wordIndex of bit i in a []uint64
//   func wordIdx(i uint) int {
//   	return int(i >> 6) // like (i / 64) but faster
//   }

//   bitIdx calculates the bitIndex of i in an `uint64`
//   func bitIdx(i uint) uint {
//   	return i & 63 // like (i % 64) but mostly faster
//   }
//
// just as an explanation of the expressions,
//
//   i>>6 or i<<6 and i&63
//
// not factored out as functions to make most of the methods
// inlineable with minimal costs.

// BitSet256 represents a fixed size bitset from [0..255]
type BitSet256 [4]uint64

// Set sets the bit.
func (b *BitSet256) Set(bit uint8) {
	b[bit>>6] |= 1 << (bit & 63)
}

// Clear clears the bit.
func (b *BitSet256) Clear(bit uint8) {
	b[bit>>6] &^= 1 << (bit & 63)
}

// Test if the bit is set.
func (b *BitSet256) Test(bit uint8) (ok bool) {
	return b[bit>>6]&(1<<(bit&63)) != 0
}

// FirstSet returns the index of the lowest (first) bit that is set in the BitSet256.
//
// It searches the 256-bit set in ascending order and returns the position of the
// first bit with value 1. If at least one bit is set, ok is true.
// If no bits are set, ok is false and first is undefined.
//
// Example:
//
//	var bs BitSet256
//	bs.Set(17)
//	bs.Set(42)
//	bs.Set(130)
//	bs.Set(255)
//	index, ok := bs.FirstSet()  // index == 17, ok == true
//
// Note: This implementation avoids a for loop for optimal speed.
// On modern CPUs, computing all four trailing-zero counts up front allows
// the CPU to parallelize these operations internally (pipelining), avoiding
// branch misprediction and maximizing instruction throughput. This technique
// is especially effective for bitsets with known, fixed word count.
func (b *BitSet256) FirstSet() (first uint8, ok bool) {
	// optimized for pipelining, can still inline with cost 79
	x0 := bits.TrailingZeros64(b[0])
	x1 := bits.TrailingZeros64(b[1])
	x2 := bits.TrailingZeros64(b[2])
	x3 := bits.TrailingZeros64(b[3])

	if x0 != 64 {
		//nolint:gosec  // G115: integer overflow conversion int -> uint
		return uint8(x0), true
	}
	if x1 != 64 {
		//nolint:gosec  // G115: integer overflow conversion int -> uint
		return uint8(x1 + 64), true
	}
	if x2 != 64 {
		//nolint:gosec  // G115: integer overflow conversion int -> uint
		return uint8(x2 + 128), true
	}
	if x3 != 64 {
		//nolint:gosec  // G115: integer overflow conversion int -> uint
		return uint8(x3 + 192), true
	}

	return
}

// NextSet returns the index of the next set bit that is greater than or equal to bit.
//
// If such a bit exists, it returns its index as next and ok=true.
// Otherwise, ok is false and next is undefined.
//
// The search starts at the given bit index and proceeds toward higher indices, scanning
// across all four 64-bit segments of the internal bitset representation.
//
// Example:
//
//	b.Set(5)
//	b.Set(130)
//	b.NextSet(0)   ->   5, true
//	b.NextSet(5)   ->   5, true
//	b.NextSet(6)   -> 130, true
//	b.NextSet(200) ->   0, false
func (b *BitSet256) NextSet(bit uint8) (next uint8, ok bool) {
	wIdx := int(bit >> 6)

	// process the first (maybe partial) word
	first := b[wIdx] >> (bit & 63)
	if first != 0 {
		//nolint:gosec  // G115: integer overflow conversion int -> uint
		return bit + uint8(bits.TrailingZeros64(first)), true
	}

	// process the following words until next bit is set
	for wIdx++; wIdx < 4; wIdx++ {
		if next := b[wIdx]; next != 0 {
			//nolint:gosec  // G115: integer overflow conversion int -> uint
			return uint8(wIdx<<6 + bits.TrailingZeros64(next)), true
		}
	}
	return
}

// LastSet returns the index of the highest (last) bit that is set in the BitSet256.
//
// It searches the bitset in descending order and returns the position of the
// first bit (top bit) with value 1. If at least one bit is set, ok is true.
// If no bits are set, ok is false and last is undefined.
//
// Example:
//
//	var bs BitSet256
//	bs.Set(2)
//	bs.Set(130)
//	bs.Set(214)
//	index, ok := bs.LastSet()  // index == 214, ok == true
func (b *BitSet256) LastSet() (last uint8, ok bool) {
	// optimized for pipelining, sorry, can't inline, cost 81>80
	// try it again when Go supports SIMD intrinsics
	//
	// ### b3 := bits.Len64(b[3])
	// ### b2 := bits.Len64(b[2])
	// ### b1 := bits.Len64(b[1])
	// ### b0 := bits.Len64(b[0])

	// ### if b3 != 0 {
	// ### 	return uint8(b3 + 191), true
	// ### }
	// ### if b2 != 0 {
	// ### 	return uint8(b2 + 127), true
	// ### }
	// ### if b1 != 0 {
	// ### 	return uint8(b1 + 63), true
	// ### }
	// ### if b0 != 0 {
	// ### 	return uint8(b0 - 1), true
	// ### }
	// ### return

	for wIdx := 3; wIdx >= 0; wIdx-- {
		if word := b[wIdx]; word != 0 {
			//nolint:gosec  // G115: integer overflow conversion int -> uint
			return uint8(wIdx<<6 + bits.Len64(word) - 1), true
		}
	}
	return
}

// AsSlice returns a slice containing all set bits in the BitSet256.
//
// The bits are returned in ascending order as uint8 values. The provided buf
// must be a pointer to an array of 256 uint8s; it is used as backing
// storage for the result to avoid heap allocations. The returned slice shares
// its backing array with buf and is only valid until buf is modified or reused.
func (b *BitSet256) AsSlice(buf *[256]uint8) []uint8 {
	size := 0
	for wIdx, word := range b {
		for ; word != 0; size++ {
			//nolint:gosec  // G115: integer overflow conversion int -> uint
			buf[size] = uint8(wIdx<<6 + bits.TrailingZeros64(word))
			word &= word - 1 // clear the rightmost set bit
		}
	}

	return buf[:size]
}

// Bits returns a slice containing all set bits in the BitSet256.
//
// The bits are returned in ascending order as uint8 values. Bits allocates
// a new slice on the heap for the result. For allocation-free collection,
// use [AsSlice] with a pre-allocated buffer.
//
// Example usage:
//
//	bits := b.Bits()
//	// bits now contains the indices of all set bits in b
func (b *BitSet256) Bits() []uint8 {
	return b.AsSlice(&[256]uint8{})
}

// IntersectionTop computes the intersection of base set with the compare set.
// If the result set isn't empty, it returns the top most set bit and true.
func (b *BitSet256) IntersectionTop(c *BitSet256) (top uint8, ok bool) {
	for wIdx := 3; wIdx >= 0; wIdx-- {
		if word := b[wIdx] & c[wIdx]; word != 0 {
			//nolint:gosec  // G115: integer overflow conversion int -> uint8
			return uint8(wIdx<<6 + bits.Len64(word) - 1), true
		}
	}
	return
}

// Rank returns the number of bits set (i.e., value 1) in the BitSet256
// up to and including the provided index.
//
// The rank is computed efficiently using precomputed bitmasks (rankMask),
// which mask out all bits above the index. For example:
//
//	b.Set(3)
//	b.Set(5)
//	b.Set(120)
//	b.Rank(5)   -> 2     // only bits 3 and 5 are ≤ 5
//	b.Rank(119) -> 2     // only bits 3 and 5 are ≤ 119
//	b.Rank(120) -> 3     // bit 120 is included here
//
// Rank is particularly useful in prefix trees, indexing schemes,
// and data compression techniques where ordinal positions matter.
//
// Internally, the function performs four bitwise-and operations
// between the bitset words and a precomputed mask covering bits 0..idx,
// followed by popcount operations (via bits.OnesCount64).
//
// This avoids dynamic mask construction and enables branch-free, highly
// predictable performance.
func (b *BitSet256) Rank(idx uint8) (rnk int) {
	rnk += bits.OnesCount64(b[0] & rankMask[idx][0])
	rnk += bits.OnesCount64(b[1] & rankMask[idx][1])
	rnk += bits.OnesCount64(b[2] & rankMask[idx][2])
	rnk += bits.OnesCount64(b[3] & rankMask[idx][3])
	return
}

// IsEmpty returns true if no bit is set.
func (b *BitSet256) IsEmpty() bool {
	return b[0]|b[1]|b[2]|b[3] == 0
}

// Intersects returns true if the intersection of base set with the compare set
// is not the empty set.
func (b *BitSet256) Intersects(c *BitSet256) bool {
	return b[0]&c[0] != 0 ||
		b[1]&c[1] != 0 ||
		b[2]&c[2] != 0 ||
		b[3]&c[3] != 0
}

// Intersection computes the intersection of base set with the compare set.
// This is the BitSet equivalent of & (and).
func (b *BitSet256) Intersection(c *BitSet256) (bs BitSet256) {
	bs[0] = b[0] & c[0]
	bs[1] = b[1] & c[1]
	bs[2] = b[2] & c[2]
	bs[3] = b[3] & c[3]
	return
}

// Union performs an in-place union of the receiver with c.
// It is the BitSet equivalent of | (OR).
func (b *BitSet256) Union(c *BitSet256) {
	b[0] |= c[0]
	b[1] |= c[1]
	b[2] |= c[2]
	b[3] |= c[3]
}

// Size is the number of set bits.
func (b *BitSet256) Size() (cnt int) {
	cnt += bits.OnesCount64(b[0])
	cnt += bits.OnesCount64(b[1])
	cnt += bits.OnesCount64(b[2])
	cnt += bits.OnesCount64(b[3])
	return
}

// rankMask is a table of bitmasks with all bits set to 1 up to and including a given bit position.
// It is used by BitSet256.Rank() to perform efficient popcount operations.
//
// This approach trades ~8KB of static memory for zero-allocation,
// fully branch-free, and cache-friendly Rank() calls with constant runtime.
//
// Used internally by the trie for position counting, CIDR ordering,
// and fast range-limited bit population counts.
//
//nolint:gochecknoglobals // Precomputed read‑only table used in hot paths.
var rankMask = [256]BitSet256{
	/*   0 */ {0x1, 0x0, 0x0, 0x0},
	/*   1 */ {0x3, 0x0, 0x0, 0x0},
	/*   2 */ {0x7, 0x0, 0x0, 0x0},
	/*   3 */ {0xf, 0x0, 0x0, 0x0},
	/*   4 */ {0x1f, 0x0, 0x0, 0x0},
	/*   5 */ {0x3f, 0x0, 0x0, 0x0},
	/*   6 */ {0x7f, 0x0, 0x0, 0x0},
	/*   7 */ {0xff, 0x0, 0x0, 0x0},
	/*   8 */ {0x1ff, 0x0, 0x0, 0x0},
	/*   9 */ {0x3ff, 0x0, 0x0, 0x0},
	/*  10 */ {0x7ff, 0x0, 0x0, 0x0},
	/*  11 */ {0xfff, 0x0, 0x0, 0x0},
	/*  12 */ {0x1fff, 0x0, 0x0, 0x0},
	/*  13 */ {0x3fff, 0x0, 0x0, 0x0},
	/*  14 */ {0x7fff, 0x0, 0x0, 0x0},
	/*  15 */ {0xffff, 0x0, 0x0, 0x0},
	/*  16 */ {0x1ffff, 0x0, 0x0, 0x0},
	/*  17 */ {0x3ffff, 0x0, 0x0, 0x0},
	/*  18 */ {0x7ffff, 0x0, 0x0, 0x0},
	/*  19 */ {0xfffff, 0x0, 0x0, 0x0},
	/*  20 */ {0x1fffff, 0x0, 0x0, 0x0},
	/*  21 */ {0x3fffff, 0x0, 0x0, 0x0},
	/*  22 */ {0x7fffff, 0x0, 0x0, 0x0},
	/*  23 */ {0xffffff, 0x0, 0x0, 0x0},
	/*  24 */ {0x1ffffff, 0x0, 0x0, 0x0},
	/*  25 */ {0x3ffffff, 0x0, 0x0, 0x0},
	/*  26 */ {0x7ffffff, 0x0, 0x0, 0x0},
	/*  27 */ {0xfffffff, 0x0, 0x0, 0x0},
	/*  28 */ {0x1fffffff, 0x0, 0x0, 0x0},
	/*  29 */ {0x3fffffff, 0x0, 0x0, 0x0},
	/*  30 */ {0x7fffffff, 0x0, 0x0, 0x0},
	/*  31 */ {0xffffffff, 0x0, 0x0, 0x0},
	/*  32 */ {0x1ffffffff, 0x0, 0x0, 0x0},
	/*  33 */ {0x3ffffffff, 0x0, 0x0, 0x0},
	/*  34 */ {0x7ffffffff, 0x0, 0x0, 0x0},
	/*  35 */ {0xfffffffff, 0x0, 0x0, 0x0},
	/*  36 */ {0x1fffffffff, 0x0, 0x0, 0x0},
	/*  37 */ {0x3fffffffff, 0x0, 0x0, 0x0},
	/*  38 */ {0x7fffffffff, 0x0, 0x0, 0x0},
	/*  39 */ {0xffffffffff, 0x0, 0x0, 0x0},
	/*  40 */ {0x1ffffffffff, 0x0, 0x0, 0x0},
	/*  41 */ {0x3ffffffffff, 0x0, 0x0, 0x0},
	/*  42 */ {0x7ffffffffff, 0x0, 0x0, 0x0},
	/*  43 */ {0xfffffffffff, 0x0, 0x0, 0x0},
	/*  44 */ {0x1fffffffffff, 0x0, 0x0, 0x0},
	/*  45 */ {0x3fffffffffff, 0x0, 0x0, 0x0},
	/*  46 */ {0x7fffffffffff, 0x0, 0x0, 0x0},
	/*  47 */ {0xffffffffffff, 0x0, 0x0, 0x0},
	/*  48 */ {0x1ffffffffffff, 0x0, 0x0, 0x0},
	/*  49 */ {0x3ffffffffffff, 0x0, 0x0, 0x0},
	/*  50 */ {0x7ffffffffffff, 0x0, 0x0, 0x0},
	/*  51 */ {0xfffffffffffff, 0x0, 0x0, 0x0},
	/*  52 */ {0x1fffffffffffff, 0x0, 0x0, 0x0},
	/*  53 */ {0x3fffffffffffff, 0x0, 0x0, 0x0},
	/*  54 */ {0x7fffffffffffff, 0x0, 0x0, 0x0},
	/*  55 */ {0xffffffffffffff, 0x0, 0x0, 0x0},
	/*  56 */ {0x1ffffffffffffff, 0x0, 0x0, 0x0},
	/*  57 */ {0x3ffffffffffffff, 0x0, 0x0, 0x0},
	/*  58 */ {0x7ffffffffffffff, 0x0, 0x0, 0x0},
	/*  59 */ {0xfffffffffffffff, 0x0, 0x0, 0x0},
	/*  60 */ {0x1fffffffffffffff, 0x0, 0x0, 0x0},
	/*  61 */ {0x3fffffffffffffff, 0x0, 0x0, 0x0},
	/*  62 */ {0x7fffffffffffffff, 0x0, 0x0, 0x0},
	/*  63 */ {0xffffffffffffffff, 0x0, 0x0, 0x0},
	/*  64 */ {0xffffffffffffffff, 0x1, 0x0, 0x0},
	/*  65 */ {0xffffffffffffffff, 0x3, 0x0, 0x0},
	/*  66 */ {0xffffffffffffffff, 0x7, 0x0, 0x0},
	/*  67 */ {0xffffffffffffffff, 0xf, 0x0, 0x0},
	/*  68 */ {0xffffffffffffffff, 0x1f, 0x0, 0x0},
	/*  69 */ {0xffffffffffffffff, 0x3f, 0x0, 0x0},
	/*  70 */ {0xffffffffffffffff, 0x7f, 0x0, 0x0},
	/*  71 */ {0xffffffffffffffff, 0xff, 0x0, 0x0},
	/*  72 */ {0xffffffffffffffff, 0x1ff, 0x0, 0x0},
	/*  73 */ {0xffffffffffffffff, 0x3ff, 0x0, 0x0},
	/*  74 */ {0xffffffffffffffff, 0x7ff, 0x0, 0x0},
	/*  75 */ {0xffffffffffffffff, 0xfff, 0x0, 0x0},
	/*  76 */ {0xffffffffffffffff, 0x1fff, 0x0, 0x0},
	/*  77 */ {0xffffffffffffffff, 0x3fff, 0x0, 0x0},
	/*  78 */ {0xffffffffffffffff, 0x7fff, 0x0, 0x0},
	/*  79 */ {0xffffffffffffffff, 0xffff, 0x0, 0x0},
	/*  80 */ {0xffffffffffffffff, 0x1ffff, 0x0, 0x0},
	/*  81 */ {0xffffffffffffffff, 0x3ffff, 0x0, 0x0},
	/*  82 */ {0xffffffffffffffff, 0x7ffff, 0x0, 0x0},
	/*  83 */ {0xffffffffffffffff, 0xfffff, 0x0, 0x0},
	/*  84 */ {0xffffffffffffffff, 0x1fffff, 0x0, 0x0},
	/*  85 */ {0xffffffffffffffff, 0x3fffff, 0x0, 0x0},
	/*  86 */ {0xffffffffffffffff, 0x7fffff, 0x0, 0x0},
	/*  87 */ {0xffffffffffffffff, 0xffffff, 0x0, 0x0},
	/*  88 */ {0xffffffffffffffff, 0x1ffffff, 0x0, 0x0},
	/*  89 */ {0xffffffffffffffff, 0x3ffffff, 0x0, 0x0},
	/*  90 */ {0xffffffffffffffff, 0x7ffffff, 0x0, 0x0},
	/*  91 */ {0xffffffffffffffff, 0xfffffff, 0x0, 0x0},
	/*  92 */ {0xffffffffffffffff, 0x1fffffff, 0x0, 0x0},
	/*  93 */ {0xffffffffffffffff, 0x3fffffff, 0x0, 0x0},
	/*  94 */ {0xffffffffffffffff, 0x7fffffff, 0x0, 0x0},
	/*  95 */ {0xffffffffffffffff, 0xffffffff, 0x0, 0x0},
	/*  96 */ {0xffffffffffffffff, 0x1ffffffff, 0x0, 0x0},
	/*  97 */ {0xffffffffffffffff, 0x3ffffffff, 0x0, 0x0},
	/*  98 */ {0xffffffffffffffff, 0x7ffffffff, 0x0, 0x0},
	/*  99 */ {0xffffffffffffffff, 0xfffffffff, 0x0, 0x0},
	/* 100 */ {0xffffffffffffffff, 0x1fffffffff, 0x0, 0x0},
	/* 101 */ {0xffffffffffffffff, 0x3fffffffff, 0x0, 0x0},
	/* 102 */ {0xffffffffffffffff, 0x7fffffffff, 0x0, 0x0},
	/* 103 */ {0xffffffffffffffff, 0xffffffffff, 0x0, 0x0},
	/* 104 */ {0xffffffffffffffff, 0x1ffffffffff, 0x0, 0x0},
	/* 105 */ {0xffffffffffffffff, 0x3ffffffffff, 0x0, 0x0},
	/* 106 */ {0xffffffffffffffff, 0x7ffffffffff, 0x0, 0x0},
	/* 107 */ {0xffffffffffffffff, 0xfffffffffff, 0x0, 0x0},
	/* 108 */ {0xffffffffffffffff, 0x1fffffffffff, 0x0, 0x0},
	/* 109 */ {0xffffffffffffffff, 0x3fffffffffff, 0x0, 0x0},
	/* 110 */ {0xffffffffffffffff, 0x7fffffffffff, 0x0, 0x0},
	/* 111 */ {0xffffffffffffffff, 0xffffffffffff, 0x0, 0x0},
	/* 112 */ {0xffffffffffffffff, 0x1ffffffffffff, 0x0, 0x0},
	/* 113 */ {0xffffffffffffffff, 0x3ffffffffffff, 0x0, 0x0},
	/* 114 */ {0xffffffffffffffff, 0x7ffffffffffff, 0x0, 0x0},
	/* 115 */ {0xffffffffffffffff, 0xfffffffffffff, 0x0, 0x0},
	/* 116 */ {0xffffffffffffffff, 0x1fffffffffffff, 0x0, 0x0},
	/* 117 */ {0xffffffffffffffff, 0x3fffffffffffff, 0x0, 0x0},
	/* 118 */ {0xffffffffffffffff, 0x7fffffffffffff, 0x0, 0x0},
	/* 119 */ {0xffffffffffffffff, 0xffffffffffffff, 0x0, 0x0},
	/* 120 */ {0xffffffffffffffff, 0x1ffffffffffffff, 0x0, 0x0},
	/* 121 */ {0xffffffffffffffff, 0x3ffffffffffffff, 0x0, 0x0},
	/* 122 */ {0xffffffffffffffff, 0x7ffffffffffffff, 0x0, 0x0},
	/* 123 */ {0xffffffffffffffff, 0xfffffffffffffff, 0x0, 0x0},
	/* 124 */ {0xffffffffffffffff, 0x1fffffffffffffff, 0x0, 0x0},
	/* 125 */ {0xffffffffffffffff, 0x3fffffffffffffff, 0x0, 0x0},
	/* 126 */ {0xffffffffffffffff, 0x7fffffffffffffff, 0x0, 0x0},
	/* 127 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0},
	/* 128 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1, 0x0},
	/* 129 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3, 0x0},
	/* 130 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7, 0x0},
	/* 131 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xf, 0x0},
	/* 132 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1f, 0x0},
	/* 133 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3f, 0x0},
	/* 134 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7f, 0x0},
	/* 135 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xff, 0x0},
	/* 136 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1ff, 0x0},
	/* 137 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3ff, 0x0},
	/* 138 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7ff, 0x0},
	/* 139 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xfff, 0x0},
	/* 140 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1fff, 0x0},
	/* 141 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3fff, 0x0},
	/* 142 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7fff, 0x0},
	/* 143 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffff, 0x0},
	/* 144 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1ffff, 0x0},
	/* 145 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3ffff, 0x0},
	/* 146 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7ffff, 0x0},
	/* 147 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xfffff, 0x0},
	/* 148 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1fffff, 0x0},
	/* 149 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3fffff, 0x0},
	/* 150 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7fffff, 0x0},
	/* 151 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffff, 0x0},
	/* 152 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1ffffff, 0x0},
	/* 153 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3ffffff, 0x0},
	/* 154 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7ffffff, 0x0},
	/* 155 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xfffffff, 0x0},
	/* 156 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1fffffff, 0x0},
	/* 157 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffff, 0x0},
	/* 158 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffff, 0x0},
	/* 159 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffff, 0x0},
	/* 160 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1ffffffff, 0x0},
	/* 161 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3ffffffff, 0x0},
	/* 162 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7ffffffff, 0x0},
	/* 163 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffff, 0x0},
	/* 164 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1fffffffff, 0x0},
	/* 165 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffff, 0x0},
	/* 166 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffff, 0x0},
	/* 167 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffff, 0x0},
	/* 168 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1ffffffffff, 0x0},
	/* 169 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3ffffffffff, 0x0},
	/* 170 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7ffffffffff, 0x0},
	/* 171 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffffff, 0x0},
	/* 172 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1fffffffffff, 0x0},
	/* 173 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffff, 0x0},
	/* 174 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffff, 0x0},
	/* 175 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffff, 0x0},
	/* 176 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1ffffffffffff, 0x0},
	/* 177 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3ffffffffffff, 0x0},
	/* 178 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7ffffffffffff, 0x0},
	/* 179 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffffffff, 0x0},
	/* 180 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1fffffffffffff, 0x0},
	/* 181 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffff, 0x0},
	/* 182 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffff, 0x0},
	/* 183 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffff, 0x0},
	/* 184 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1ffffffffffffff, 0x0},
	/* 185 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3ffffffffffffff, 0x0},
	/* 186 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7ffffffffffffff, 0x0},
	/* 187 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffffffffff, 0x0},
	/* 188 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x1fffffffffffffff, 0x0},
	/* 189 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff, 0x0},
	/* 190 */ {0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff, 0x0},
	/* 191 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x0},
	/* 192 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1},
	/* 193 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3},
	/* 194 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7},
	/* 195 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xf},
	/* 196 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1f},
	/* 197 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3f},
	/* 198 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7f},
	/* 199 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xff},
	/* 200 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1ff},
	/* 201 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3ff},
	/* 202 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7ff},
	/* 203 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfff},
	/* 204 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1fff},
	/* 205 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fff},
	/* 206 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fff},
	/* 207 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffff},
	/* 208 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1ffff},
	/* 209 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3ffff},
	/* 210 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7ffff},
	/* 211 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffff},
	/* 212 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1fffff},
	/* 213 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffff},
	/* 214 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffff},
	/* 215 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffff},
	/* 216 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1ffffff},
	/* 217 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3ffffff},
	/* 218 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7ffffff},
	/* 219 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffff},
	/* 220 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1fffffff},
	/* 221 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffff},
	/* 222 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffff},
	/* 223 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffff},
	/* 224 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1ffffffff},
	/* 225 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3ffffffff},
	/* 226 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7ffffffff},
	/* 227 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffff},
	/* 228 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1fffffffff},
	/* 229 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffff},
	/* 230 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffff},
	/* 231 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffff},
	/* 232 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1ffffffffff},
	/* 233 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3ffffffffff},
	/* 234 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7ffffffffff},
	/* 235 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffffff},
	/* 236 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1fffffffffff},
	/* 237 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffff},
	/* 238 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffff},
	/* 239 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffff},
	/* 240 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1ffffffffffff},
	/* 241 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3ffffffffffff},
	/* 242 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7ffffffffffff},
	/* 243 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffffffff},
	/* 244 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1fffffffffffff},
	/* 245 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffff},
	/* 246 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffff},
	/* 247 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffff},
	/* 248 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1ffffffffffffff},
	/* 249 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3ffffffffffffff},
	/* 250 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7ffffffffffffff},
	/* 251 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffffffffff},
	/* 252 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x1fffffffffffffff},
	/* 253 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff},
	/* 254 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff},
	/* 255 */ {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
}
