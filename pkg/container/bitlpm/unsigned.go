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

// NewUintTrie represents a Trie with a key of any
// uint type.
func NewUintTrie[K Unsigned, T any]() Trie[K, T] {
	var k K
	size := uint(unsafe.Sizeof(k))
	return &trieUint[K, T]{NewTrie[K, T](size * 8), size, size * 8}
}

type trieUint[K Unsigned, T any] struct {
	t                  Trie[Key[K], T]
	keySize, maxPrefix uint
}

func (tu *trieUint[K, T]) getKey(k K) Key[K] {
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

func (tu *trieUint[K, T]) Upsert(prefix uint, k K, value T) {
	tu.t.Upsert(prefix, tu.getKey(k), value)
}

func (tu *trieUint[K, T]) Delete(prefix uint, k K) bool {
	return tu.t.Delete(prefix, tu.getKey(k))
}

func (tu *trieUint[K, T]) Lookup(k K) (T, bool) {
	return tu.t.Lookup(tu.getKey(k))
}

func (tu *trieUint[K, T]) Ancestors(prefix uint, k K, fn func(prefix uint, key K, value T) bool) {
	tu.t.Ancestors(prefix, tu.getKey(k), func(prefix uint, k Key[K], v T) bool {
		return fn(prefix, k.Value(), v)
	})
}

func (tu *trieUint[K, T]) Descendants(prefix uint, k K, fn func(prefix uint, key K, value T) bool) {
	tu.t.Descendants(prefix, tu.getKey(k), func(prefix uint, k Key[K], v T) bool {
		return fn(prefix, k.Value(), v)
	})
}

func (tu *trieUint[K, T]) Len() uint {
	return tu.t.Len()
}

func (tu *trieUint[K, T]) ForEach(fn func(prefix uint, key K, value T) bool) {
	tu.t.ForEach(func(prefix uint, k Key[K], v T) bool {
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
