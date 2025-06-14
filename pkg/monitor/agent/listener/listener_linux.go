// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package listener

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// IsDisconnected is a convenience function that wraps the absurdly long set of
// checks for a disconnect.
func IsDisconnected(err error) bool {
	if err == nil {
		return false
	}

	op := &net.OpError{}
	if !errors.As(err, &op) {
		return false
	}

	syscerr := &os.SyscallError{}
	if !errors.As(op.Err, &syscerr) {
		return false
	}

	var errn unix.Errno
	return errors.As(syscerr.Err, &errn) && errors.Is(errn, unix.EPIPE)
}
