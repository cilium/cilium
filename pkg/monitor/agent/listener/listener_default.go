// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux
// +build !linux

package listener

import (
	"errors"
	"net"
	"os"

	"syscall"
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

	var errn syscall.Errno
	return errors.As(syscerr.Err, &errn) && errors.Is(errn, syscall.EPIPE)
}
