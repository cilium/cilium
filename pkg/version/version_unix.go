// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package version

import (
	"github.com/blang/semver/v4"
	"golang.org/x/sys/unix"
)

// GetKernelVersion returns the version of the Linux kernel running on this host.
func GetKernelVersion() (semver.Version, error) {
	var unameBuf unix.Utsname
	if err := unix.Uname(&unameBuf); err != nil {
		return semver.Version{}, err
	}
	return ParseKernelVersion(string(unameBuf.Release[:]))
}
