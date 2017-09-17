// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build linux,386

package afpacket

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	sysSETSOCKOPT = 0xe
	sysGETSOCKOPT = 0xf
)

func socketcall(call int, a0, a1, a2, a3, a4, a5 uintptr) (int, unix.Errno)

// setsockopt provides access to the setsockopt syscall.
func setsockopt(fd, level, name int, v unsafe.Pointer, l uintptr) error {
	_, errno := socketcall(
		sysSETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(v),
		l,
		0,
	)
	if errno != 0 {
		return error(errno)
	}

	return nil
}

func getsockopt(fd, level, name int, v unsafe.Pointer, l uintptr) error {
	_, errno := socketcall(
		sysGETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(v),
		l,
		0,
	)
	if errno != 0 {
		return error(errno)
	}

	return nil
}
