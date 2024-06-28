// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import (
	"fmt"
	"math/bits"
	"unsafe"
)

// Unsigned represents all types that have an underlying
// unsigned integer type, excluding uintptr and uint.
type Unsigned interface {
	~uint8 | ~uint16 | ~uint32 | ~uint64
}

// UintTrie uses all unsigned integer types
// except for uintptr and uint.
type UintTrie[K Unsigned, V any] struct {
	trie    Trie[Key[K], V]
	keySize uint
}

// NewUintTrie represents a Trie with a key of any
// uint type.
func NewUintTrie[K Unsigned, T any]() *UintTrie[K, T] {
	var k K
	size := uint(unsafe.Sizeof(k))
	return &UintTrie[K, T]{
		trie:    NewTrie[K, T](size * 8),
		keySize: size,
	}
}

func (tu *UintTrie[K, T]) getKey(k K) Key[K] {
	switch tu.keySize {
	case 1:
		return unsignedKey8[K](k)
	case 2:
		return unsignedKey16[K](k)
	case 4:
		return unsignedKey32[K](k)
	case 8:
		return unsignedKey64[K](k)
	}
	panic(fmt.Sprintf("unexpected key size of %d", unsafe.Sizeof(k)))
}

func (ut *UintTrie[K, T]) Upsert(prefix uint, k K, value T) {
	ut.trie.Upsert(prefix, ut.getKey(k), value)
}

func (ut *UintTrie[K, T]) Delete(prefix uint, k K) bool {
	return ut.trie.Delete(prefix, ut.getKey(k))
}

func (ut *UintTrie[K, T]) ExactLookup(prefix uint, k K) (T, bool) {
	return ut.trie.ExactLookup(prefix, ut.getKey(k))
}

func (ut *UintTrie[K, T]) LongestPrefixMatch(k K) (T, bool) {
	return ut.trie.LongestPrefixMatch(ut.getKey(k))
}

func (ut *UintTrie[K, T]) Ancestors(prefix uint, k K, fn func(prefix uint, key K, value T) bool) {
	ut.trie.Ancestors(prefix, ut.getKey(k), func(prefix uint, k Key[K], v T) bool {
		return fn(prefix, k.Value(), v)
	})
}

func (ut *UintTrie[K, T]) Descendants(prefix uint, k K, fn func(prefix uint, key K, value T) bool) {
	ut.trie.Descendants(prefix, ut.getKey(k), func(prefix uint, k Key[K], v T) bool {
		return fn(prefix, k.Value(), v)
	})
}

func (ut *UintTrie[K, T]) Len() uint {
	return ut.trie.Len()
}

func (ut *UintTrie[K, T]) ForEach(fn func(prefix uint, key K, value T) bool) {
	ut.trie.ForEach(func(prefix uint, k Key[K], v T) bool {
		return fn(prefix, k.Value(), v)
	})
}

type unsignedKey8[U Unsigned] uint8

func (u unsignedKey8[U]) CommonPrefix(v U) uint {
	return uint(bits.LeadingZeros8(uint8(U(u) ^ v)))
}

func (u unsignedKey8[U]) BitValueAt(i uint) uint8 {
	if u&(1<<(7-i)) == 0 {
		return 0
	}
	return 1
}

func (u unsignedKey8[U]) Value() U {
	return U(u)
}

type unsignedKey16[U Unsigned] uint16

func (u unsignedKey16[U]) CommonPrefix(v U) uint {
	return uint(bits.LeadingZeros16(uint16(u) ^ uint16(v)))
}

func (u unsignedKey16[U]) BitValueAt(i uint) uint8 {
	if u&(1<<(15-i)) == 0 {
		return 0
	}
	return 1
}

func (u unsignedKey16[U]) Value() U {
	return U(u)
}

type unsignedKey32[U Unsigned] uint32

func (u unsignedKey32[U]) CommonPrefix(v U) uint {
	return uint(bits.LeadingZeros32(uint32(u) ^ uint32(v)))
}

func (u unsignedKey32[U]) BitValueAt(i uint) uint8 {
	if u&(1<<(31-i)) == 0 {
		return 0
	}
	return 1
}

func (u unsignedKey32[U]) Value() U {
	return U(u)
}

type unsignedKey64[U Unsigned] uint64

func (u unsignedKey64[U]) CommonPrefix(v U) uint {
	return uint(bits.LeadingZeros64(uint64(u) ^ uint64(v)))
}

func (u unsignedKey64[U]) BitValueAt(i uint) uint8 {
	if u&(1<<(63-i)) == 0 {
		return 0
	}
	return 1
}

func (u unsignedKey64[U]) Value() U {
	return U(u)
}
