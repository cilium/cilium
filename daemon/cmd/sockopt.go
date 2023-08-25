// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// setsockoptReuseAddrAndPort sets the SO_REUSEADDR and SO_REUSEPORT socket options on c's
// underlying socket in order to improve the chance to re-bind to the same address and port
// upon restart.
func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	var soerr error
	if err := c.Control(func(su uintptr) {
		s := int(su)
		// Allow reuse of recently-used addresses. This socket option is
		// set by default on listeners in Go's net package, see
		// net setDefaultListenerSockopts
		if err := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			soerr = fmt.Errorf("failed to setsockopt(SO_REUSEADDR): %w", err)
			return
		}
		// Allow reuse of recently-used ports. This gives the agent a
		// better chance to re-bind upon restarts.
		if err := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			soerr = fmt.Errorf("failed to setsockopt(SO_REUSEPORT): %w", err)
		}
	}); err != nil {
		return err
	}
	return soerr
}
