// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import "bytes"

type Key = []byte

// KeySet is a sequence of (length, byte slice) pairs.
// length is encoded as 16-bit big-endian unsigned int.
type KeySet struct {
	buf Key
}

func NewKeySet(keys ...Key) KeySet {
	size := 2 * len(keys)
	for _, k := range keys {
		size += len(k)
	}
	ks := KeySet{make([]byte, 0, size)}
	for _, k := range keys {
		ks.Append(k)
	}
	return ks
}

func (ks KeySet) First() Key {
	if len(ks.buf) < 2 {
		return nil
	}
	length := uint16(ks.buf[0])<<8 | uint16(ks.buf[1])
	return ks.buf[2 : 2+length]
}

func (ks *KeySet) Append(k Key) {
	if len(k) > 2<<16 {
		panic("keyset.Append: key too long, maximum is 64kB")
	}
	ks.buf = append(append(ks.buf, byte(len(k)>>8), byte(len(k)&0xff)), k...)
}

func (ks KeySet) Foreach(fn func(Key)) {
	for len(ks.buf) >= 2 {
		length := uint16(ks.buf[0])<<8 | uint16(ks.buf[1])
		fn(append([]byte(nil), ks.buf[2:2+length]...))
		ks.buf = ks.buf[2+length:]
	}
}

func (ks KeySet) Exists(k Key) bool {
	buf := ks.buf
	for len(buf) >= 2 {
		length := uint16(buf[0])<<8 | uint16(buf[1])
		k2 := buf[2 : 2+length]
		if bytes.Equal(k, k2) {
			return true
		}
		buf = buf[2+length:]
	}
	return false
}
