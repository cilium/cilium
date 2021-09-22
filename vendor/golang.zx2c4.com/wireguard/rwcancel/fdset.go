// +build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package rwcancel

import "golang.org/x/sys/unix"

type fdSet struct {
	unix.FdSet
}

func (fdset *fdSet) set(i int) {
	bits := 32 << (^uint(0) >> 63)
	fdset.Bits[i/bits] |= 1 << uint(i%bits)
}

func (fdset *fdSet) check(i int) bool {
	bits := 32 << (^uint(0) >> 63)
	return (fdset.Bits[i/bits] & (1 << uint(i%bits))) != 0
}
