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
