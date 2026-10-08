// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ethtool

import (
	"bytes"

	"golang.org/x/sys/unix"
)

func IsVirtualDriver(iface string) (bool, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)

	info, err := unix.IoctlGetEthtoolDrvinfo(fd, iface)
	if err != nil {
		return false, err
	}
	return string(bytes.TrimRight(info.Driver[:], "\x00")) == "veth", nil
}
