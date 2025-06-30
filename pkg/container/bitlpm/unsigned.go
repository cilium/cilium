// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import (
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
	trie    Trie[unsignedKey[K], V]
	keySize uint
}

// NewUintTrie represents a Trie with a key of any
// uint type.
func NewUintTrie[K Unsigned, T any]() *UintTrie[K, T] {
	var k K
	size := uint(unsafe.Sizeof(k))
	return &UintTrie[K, T]{
		trie:    NewTrie[unsignedKey[K], T](size * 8),
		keySize: size,
	}
}

func (ut *UintTrie[K, T]) Upsert(prefix uint, k K, value T) bool {
	return ut.trie.Upsert(prefix, unsignedKey[K]{value: k}, value)
}

func (ut *UintTrie[K, T]) Delete(prefix uint, k K) bool {
	return ut.trie.Delete(prefix, unsignedKey[K]{value: k})
}

func (ut *UintTrie[K, T]) ExactLookup(prefix uint, k K) (T, bool) {
	return ut.trie.ExactLookup(prefix, unsignedKey[K]{value: k})
}

func (ut *UintTrie[K, T]) LongestPrefixMatch(k K) (K, T, bool) {
	k2, v, ok := ut.trie.LongestPrefixMatch(unsignedKey[K]{value: k})
	if ok {
		return k2.value, v, ok
	}
	var empty K
	return empty, v, ok
}

func (ut *UintTrie[K, T]) Ancestors(prefix uint, k K, fn func(prefix uint, key K, value T) bool) {
	ut.trie.Ancestors(prefix, unsignedKey[K]{value: k}, func(prefix uint, k unsignedKey[K], v T) bool {
		return fn(prefix, k.value, v)
	})
}

func (ut *UintTrie[K, T]) Descendants(prefix uint, k K, fn func(prefix uint, key K, value T) bool) {
	ut.trie.Descendants(prefix, unsignedKey[K]{value: k}, func(prefix uint, k unsignedKey[K], v T) bool {
		return fn(prefix, k.value, v)
	})
}

func (ut *UintTrie[K, T]) Len() uint {
	return ut.trie.Len()
}

func (ut *UintTrie[K, T]) ForEach(fn func(prefix uint, key K, value T) bool) {
	ut.trie.ForEach(func(prefix uint, k unsignedKey[K], v T) bool {
		return fn(prefix, k.value, v)
	})
}

type unsignedKey[U Unsigned] struct {
	value U
}

func (u unsignedKey[U]) CommonPrefix(v unsignedKey[U]) uint {
	switch any(u.value).(type) {
	case uint8:
		return uint(bits.LeadingZeros8(uint8(u.value ^ v.value)))
	case uint16:
		return uint(bits.LeadingZeros16(uint16(u.value ^ v.value)))
	case uint32:
		return uint(bits.LeadingZeros32(uint32(u.value ^ v.value)))
	case uint64:
		return uint(bits.LeadingZeros64(uint64(u.value ^ v.value)))
	}
	return 0
}

func (u unsignedKey[U]) BitValueAt(i uint) uint8 {
	switch any(u.value).(type) {
	case uint8:
		if u.value&(1<<(7-i)) == 0 {
			return 0
		}
	case uint16:
		if u.value&(1<<(15-i)) == 0 {
			return 0
		}
	case uint32:
		if u.value&(1<<(31-i)) == 0 {
			return 0
		}
	case uint64:
		if u.value&(1<<(63-i)) == 0 {
			return 0
		}
	}
	return 1
}
