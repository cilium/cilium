// SPDX-License-Identifier: MIT
// Copyright (c) 2014 Derek Parker
// Original from https://github.com/go-delve/delve/tree/v1.26.1/pkg/dwarf/leb128

package leb128

import (
	"io"
)

// EncodeUnsigned encodes x to the unsigned Little Endian Base 128 format.
func EncodeUnsigned(out io.ByteWriter, x uint64) {
	for {
		b := byte(x & 0x7f)
		x = x >> 7
		if x != 0 {
			b = b | 0x80
		}
		out.WriteByte(b)
		if x == 0 {
			break
		}
	}
}

// EncodeSigned encodes x to the signed Little Endian Base 128 format.
func EncodeSigned(out io.ByteWriter, x int64) {
	for {
		b := byte(x & 0x7f)
		x >>= 7

		signb := b & 0x40

		last := false
		if (x == 0 && signb == 0) || (x == -1 && signb != 0) {
			last = true
		} else {
			b = b | 0x80
		}
		out.WriteByte(b)

		if last {
			break
		}
	}
}
