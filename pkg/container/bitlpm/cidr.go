// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import (
	"math/bits"
	"net/netip"
	"unsafe"
)

// CIDRTrie can hold both IPv4 and IPv6 prefixes
// at the same time.
type CIDRTrie[T any] struct {
	v4 Trie[Key[netip.Prefix], T]
	v6 Trie[Key[netip.Prefix], T]
}

// NewCIDRTrie creates a new CIDRTrie[T any].
func NewCIDRTrie[T any]() *CIDRTrie[T] {
	return &CIDRTrie[T]{
		v4: NewTrie[netip.Prefix, T](32),
		v6: NewTrie[netip.Prefix, T](128),
	}
}

// ExactLookup returns the value for a given CIDR, but only
// if there is an exact match for the CIDR in the Trie.
func (c *CIDRTrie[T]) ExactLookup(cidr netip.Prefix) (T, bool) {
	return c.treeForFamily(cidr).ExactLookup(uint(cidr.Bits()), cidrKey(cidr))
}

// LongestPrefixMatch returns the longest matched value for a given address.
func (c *CIDRTrie[T]) LongestPrefixMatch(addr netip.Addr) (netip.Prefix, T, bool) {
	if !addr.IsValid() {
		var p netip.Prefix
		var def T
		return p, def, false
	}
	bits := addr.BitLen()
	prefix := netip.PrefixFrom(addr, bits)
	k, v, ok := c.treeForFamily(prefix).LongestPrefixMatch(cidrKey(prefix))
	if ok {
		return k.Value(), v, ok
	}
	var p netip.Prefix
	return p, v, ok
}

// Ancestors iterates over every CIDR pair that contains the CIDR argument.
func (c *CIDRTrie[T]) Ancestors(cidr netip.Prefix, fn func(k netip.Prefix, v T) bool) {
	c.treeForFamily(cidr).Ancestors(uint(cidr.Bits()), cidrKey(cidr), func(prefix uint, k Key[netip.Prefix], v T) bool {
		return fn(k.Value(), v)
	})
}

// AncestorsLongestPrefixFirst iterates over every CIDR pair that contains the CIDR argument,
// longest matching prefix first, then iterating towards the root of the trie.
func (c *CIDRTrie[T]) AncestorsLongestPrefixFirst(cidr netip.Prefix, fn func(k netip.Prefix, v T) bool) {
	c.treeForFamily(cidr).AncestorsLongestPrefixFirst(uint(cidr.Bits()), cidrKey(cidr), func(prefix uint, k Key[netip.Prefix], v T) bool {
		return fn(k.Value(), v)
	})
}

// Descendants iterates over every CIDR that is contained by the CIDR argument.
func (c *CIDRTrie[T]) Descendants(cidr netip.Prefix, fn func(k netip.Prefix, v T) bool) {
	c.treeForFamily(cidr).Descendants(uint(cidr.Bits()), cidrKey(cidr), func(prefix uint, k Key[netip.Prefix], v T) bool {
		return fn(k.Value(), v)
	})
}

// DescendantsShortestPrefixFirst iterates over every CIDR that is contained by the CIDR argument.
func (c *CIDRTrie[T]) DescendantsShortestPrefixFirst(cidr netip.Prefix, fn func(k netip.Prefix, v T) bool) {
	c.treeForFamily(cidr).DescendantsShortestPrefixFirst(uint(cidr.Bits()), cidrKey(cidr), func(prefix uint, k Key[netip.Prefix], v T) bool {
		return fn(k.Value(), v)
	})
}

// Upsert adds or updates the value for a given prefix.
func (c *CIDRTrie[T]) Upsert(cidr netip.Prefix, v T) bool {
	return c.treeForFamily(cidr).Upsert(uint(cidr.Bits()), cidrKey(cidr), v)
}

// Delete removes a given prefix from the tree.
func (c *CIDRTrie[T]) Delete(cidr netip.Prefix) bool {
	return c.treeForFamily(cidr).Delete(uint(cidr.Bits()), cidrKey(cidr))
}

// Len returns the total number of ipv4 and ipv6 prefixes in the trie.
func (c *CIDRTrie[T]) Len() uint {
	return c.v4.Len() + c.v6.Len()
}

// ForEach iterates over every element of the Trie. It iterates over IPv4
// keys first.
func (c *CIDRTrie[T]) ForEach(fn func(k netip.Prefix, v T) bool) {
	var v4Break bool
	c.v4.ForEach(func(prefix uint, k Key[netip.Prefix], v T) bool {
		if !fn(k.Value(), v) {
			v4Break = true
			return false
		}
		return true
	})
	if !v4Break {
		c.v6.ForEach(func(prefix uint, k Key[netip.Prefix], v T) bool {
			return fn(k.Value(), v)
		})
	}

}

func (c *CIDRTrie[T]) treeForFamily(cidr netip.Prefix) Trie[Key[netip.Prefix], T] {
	if cidr.Addr().Is6() {
		return c.v6
	}
	return c.v4
}

type cidrKey netip.Prefix

func (k cidrKey) Value() netip.Prefix {
	return netip.Prefix(k)
}

func (k cidrKey) BitValueAt(idx uint) uint8 {
	addr := netip.Prefix(k).Addr()
	if addr.Is4() {
		word := (*(*[2]uint64)(unsafe.Pointer(&addr)))[1]
		return uint8((word >> (31 - idx)) & 1)
	}
	if idx < 64 {
		word := (*(*[2]uint64)(unsafe.Pointer(&addr)))[0]
		return uint8((word >> (63 - idx)) & 1)
	} else {
		word := (*(*[2]uint64)(unsafe.Pointer(&addr)))[1]
		return uint8((word >> (127 - idx)) & 1)
	}
}

func (k cidrKey) CommonPrefix(k2 netip.Prefix) uint {
	addr1 := netip.Prefix(k).Addr()
	addr2 := k2.Addr()
	words1 := (*[2]uint64)(unsafe.Pointer(&addr1))
	words2 := (*[2]uint64)(unsafe.Pointer(&addr2))
	if addr1.Is4() {
		word1 := uint32((*words1)[1])
		word2 := uint32((*words2)[1])
		return uint(bits.LeadingZeros32(word1 ^ word2))
	}
	v := bits.LeadingZeros64((*words1)[0] ^ (*words2)[0])
	if v == 64 {
		v += bits.LeadingZeros64((*words1)[1] ^ (*words2)[1])
	}
	return uint(v)
}
