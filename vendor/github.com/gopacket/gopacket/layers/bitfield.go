// Copyright 2021 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

type bitfield [1024]uint64

// set sets bit i in bitfield b to 1.
func (b *bitfield) set(i uint16) {
	b[i>>6] |= (1 << (i & 0x3f))
}

// has reports whether bit i is set to 1 in bitfield b.
func (b *bitfield) has(i uint16) bool {
	return b[i>>6]&(1<<(i&0x3f)) != 0
}
