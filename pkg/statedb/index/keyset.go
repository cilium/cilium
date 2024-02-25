// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import (
	"bytes"
)

// Key is a byte slice describing a key used in an index by statedb.
// If a key is variable-sized, then it must be either terminated with
// e.g. zero byte or it must be length-encoded. If it is not, then
// a Get() may return results that don't match the query (e.g. objects
// indexed with a key that has the same prefix but are longer).
// The reason is that Get() is implemented as a prefix seek to avoid
// full key comparison on iteration and also to support the
// non-unique indexes which key on "secondary + primary" keys.
type Key []byte

func (k Key) Equal(k2 Key) bool {
	return bytes.Equal(k, k2)
}

type KeySet struct {
	head Key
	tail []Key
}

func (ks KeySet) First() Key {
	return ks.head
}

func (ks KeySet) Foreach(fn func(Key)) {
	if ks.head == nil {
		return
	}
	fn(ks.head)
	for _, k := range ks.tail {
		fn(k)
	}
}

func (ks KeySet) Exists(k Key) bool {
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

func NewKeySet(keys ...Key) KeySet {
	if len(keys) == 0 {
		return KeySet{}
	}
	return KeySet{keys[0], keys[1:]}
}
