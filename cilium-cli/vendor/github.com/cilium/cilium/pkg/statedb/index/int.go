// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import (
	"encoding/binary"
)

// The indexing functions on integers should use big-endian encoding.
// This allows prefix searching on integers as the most significant
// byte is first.
// For example to find 16-bit key larger than 260 (0x0104) from 3 (0x0003)
// and 270 (0x0109)
//   00 (3) < 01 (260) => skip,
//   01 (270) >= 01 (260) => 09 > 04 => found!

func Int(n int) Key {
	return Uint64(uint64(n))
}

func Uint64(n uint64) Key {
	return binary.BigEndian.AppendUint64(nil, n)
}

func Uint32(n uint32) Key {
	return binary.BigEndian.AppendUint32(nil, n)
}

func Uint16(n uint16) Key {
	return binary.BigEndian.AppendUint16(nil, n)
}
