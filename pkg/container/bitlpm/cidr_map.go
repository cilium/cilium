// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import "net/netip"

// CIDRTrieMap holds a map of CIDRTries, keyed by a generic comparable type,
// where each trie is capable of storing both IPv4 and IPv6 prefixes at the same time.
type CIDRTrieMap[K comparable, T any] struct {
	m map[K]*CIDRTrie[T]
}

// NewCIDRTrieMap creates a new CIDRTrieMap[K comparable, T any].
func NewCIDRTrieMap[K comparable, T any]() *CIDRTrieMap[K, T] {
	return &CIDRTrieMap[K, T]{make(map[K]*CIDRTrie[T])}
}

// Descendants iterates over every CIDR that is contained by the CIDR argument in the trie identified by key.
func (cm *CIDRTrieMap[K, T]) Descendants(key K, cidr netip.Prefix, fn func(k netip.Prefix, v T) bool) {
	if cm.m[key] == nil {
		return
	}
	cm.m[key].Descendants(cidr, fn)
}

// Upsert adds or updates the value for a given prefix in the trie identified by key.
// If the key has no trie associated, a new empty one is created.
func (cm *CIDRTrieMap[K, T]) Upsert(key K, cidr netip.Prefix, v T) bool {
	if cm.m[key] == nil {
		cm.m[key] = NewCIDRTrie[T]()
	}
	return cm.m[key].Upsert(cidr, v)
}

// Delete removes a given prefix from the trie identified by key.
func (cm *CIDRTrieMap[K, T]) Delete(key K, cidr netip.Prefix) bool {
	if cm.m[key] == nil {
		return false
	}
	found := cm.m[key].Delete(cidr)
	if cm.m[key].Len() == 0 {
		delete(cm.m, key)
	}
	return found
}
