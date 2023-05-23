// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probe

import (
	"errors"

	"golang.org/x/sys/unix"
)

// HaveIPv6Support tests whether kernel can open an IPv6 socket. This will
// also implicitly auto-load IPv6 kernel module if available and not yet
// loaded.
func HaveIPv6Support() bool {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) {
		return false
	}
	unix.Close(fd)
	return true
}
