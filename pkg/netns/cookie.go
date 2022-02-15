// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netns

import (
	"golang.org/x/sys/unix"
)

const SO_NETNS_COOKIE = 71

// GetNetNSCookie tries to retrieve the cookie of the host netns.
func GetNetNSCookie() (uint64, error) {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(s)

	cookie, err := unix.GetsockoptUint64(s, unix.SOL_SOCKET, SO_NETNS_COOKIE)
	if err != nil {
		return 0, err
	}

	return cookie, nil
}
