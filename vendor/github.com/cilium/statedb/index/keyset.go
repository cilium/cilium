// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import (
	"bytes"
)

// Key is a byte slice describing a key used in an index by statedb.
type Key []byte

func (k Key) Equal(k2 Key) bool {
	return bytes.Equal(k, k2)
}

// KeySet is a collection of keys used to index an object. Its zero value is
// an empty set; a nil key supplied to NewKeySet is a valid zero-length key.
type KeySet struct {
	head    Key
	tail    []Key
	hasHead bool
}

// Len returns the number of keys in the set.
func (ks KeySet) Len() int {
	if !ks.hasHead {
		return 0
	}
	return 1 + len(ks.tail)
}

// First returns the first key in the set, or false if the set is empty.
func (ks KeySet) First() (Key, bool) {
	return ks.head, ks.hasHead
}

// Foreach calls fn for each key in the set.
func (ks KeySet) Foreach(fn func(Key)) {
	if !ks.hasHead {
		return
	}
	fn(ks.head)
	for _, k := range ks.tail {
		fn(k)
	}
}

func (ks KeySet) Exists(k Key) bool {
	if !ks.hasHead {
		return false
	}
	if ks.head.Equal(k) {
		return true
	}
	for _, k2 := range ks.tail {
		if k2.Equal(k) {
			return true
		}
	}
	return false
}

// EmptyKeySet is a KeySet containing no keys.
var EmptyKeySet KeySet

// NewKeySet constructs a non-empty set from keys. Every argument is a key,
// including a nil or zero-length key.
func NewKeySet(key Key, keys ...Key) KeySet {
	return KeySet{head: key, tail: keys, hasHead: true}
}

func keySet(keys []Key) KeySet {
	if len(keys) == 0 {
		return EmptyKeySet
	}
	return NewKeySet(keys[0], keys[1:]...)
}
