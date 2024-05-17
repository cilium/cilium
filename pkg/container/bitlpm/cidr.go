// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import (
	"math/bits"
	"net/netip"
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
func (c *CIDRTrie[T]) LongestPrefixMatch(addr netip.Addr) (T, bool) {
	if !addr.IsValid() {
		var def T
		return def, false
	}
	bits := addr.BitLen()
	prefix := netip.PrefixFrom(addr, bits)
	return c.treeForFamily(prefix).LongestPrefixMatch(cidrKey(prefix))
}

// Ancestors iterates over every CIDR pair that contains the CIDR argument.
func (c *CIDRTrie[T]) Ancestors(cidr netip.Prefix, fn func(k netip.Prefix, v T) bool) {
	c.treeForFamily(cidr).Ancestors(uint(cidr.Bits()), cidrKey(cidr), func(prefix uint, k Key[netip.Prefix], v T) bool {
		return fn(k.Value(), v)
	})
}

// Descendants iterates over every CIDR that is contained by the CIDR argument.
func (c *CIDRTrie[T]) Descendants(cidr netip.Prefix, fn func(k netip.Prefix, v T) bool) {
	c.treeForFamily(cidr).Descendants(uint(cidr.Bits()), cidrKey(cidr), func(prefix uint, k Key[netip.Prefix], v T) bool {
		return fn(k.Value(), v)
	})
}

// Upsert adds or updates the value for a given prefix.
func (c *CIDRTrie[T]) Upsert(cidr netip.Prefix, v T) {
	c.treeForFamily(cidr).Upsert(uint(cidr.Bits()), cidrKey(cidr), v)
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
	bytes := netip.Prefix(k).Addr().AsSlice()
	byt := bytes[idx/8]
	if byt&(1<<(7-(idx%8))) == 0 {
		return 0
	}
	return 1
}

func (k cidrKey) CommonPrefix(k2 netip.Prefix) uint {
	out := uint(0)
	b1 := k.Value().Addr().AsSlice()
	b2 := k2.Addr().AsSlice()

	for i := range b1 {
		v := bits.LeadingZeros8(b1[i] ^ b2[i])
		out += uint(v)
		if v != 8 {
			break
		}
	}
	return out
}
