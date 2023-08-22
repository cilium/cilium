// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import (
	"encoding/binary"
)

func Int(n int) Key {
	return Uint64(uint64(n))
}

func Uint64(n uint64) Key {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return buf
}

func Uint16(n uint16) Key {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, n)
	return buf
}
