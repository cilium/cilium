// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2021 Authors of Cilium

//go:build !windows
// +build !windows

package version

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/cilium/cilium/pkg/versioncheck"
	"golang.org/x/sys/unix"
)

func parseKernelVersion(ver string) (semver.Version, error) {
	verStrs := strings.Split(ver, ".")
	switch {
	case len(verStrs) < 2:
		return semver.Version{}, fmt.Errorf("unable to get kernel version from %q", ver)
	case len(verStrs) < 3:
		verStrs = append(verStrs, "0")
	}
	// We are assuming the kernel version will be something as:
	// 4.9.17-040917-generic

	// If verStrs is []string{ "4", "9", "17-040917-generic" }
	// then we need to retrieve patch number.
	patch := regexp.MustCompilePOSIX(`^[0-9]+`).FindString(verStrs[2])
	if patch == "" {
		verStrs[2] = "0"
	} else {
		verStrs[2] = patch
	}
	return versioncheck.Version(strings.Join(verStrs[:3], "."))
}

// GetKernelVersion returns the version of the Linux kernel running on this host.
func GetKernelVersion() (semver.Version, error) {
	var unameBuf unix.Utsname
	if err := unix.Uname(&unameBuf); err != nil {
		return semver.Version{}, err
	}
	return parseKernelVersion(string(unameBuf.Release[:]))
}
