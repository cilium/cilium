// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !js && !plan9 && !windows
// +build !js,!plan9,!windows

package agent

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setsockoptReuseAddrAndPort sets the SO_REUSEADDR and SO_REUSEPORT socket
// options on c's underlying socket in order to increase the chance to re-bind()
// to the same address and port upon agent restart.
func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	var soerr error
	if err := c.Control(func(su uintptr) {
		sock := int(su)
		// Allow reuse of recently-used addresses. This socket option is
		// set by default on listeners in Go's net package, see
		// net.setDefaultSockopts.
		soerr = unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if soerr != nil {
			return
		}
		// Allow reuse of recently-used ports. This gives the agent a
		// better chance to re-bind upon restarts.
		soerr = unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return soerr
}
