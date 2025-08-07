// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package version

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/blang/semver/v4"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/versioncheck"
)

func parseKernelVersion(ver string) (semver.Version, error) {
	// Trim null bytes and whitespace that may come from C strings
	ver = strings.TrimRight(ver, "\x00")
	ver = strings.TrimSpace(ver)

	verStrs := strings.Split(ver, ".")

	// We are assuming the kernel version will be one of the following:
	// 4.9.17-040917-generic or 4.9-040917-generic or 4-generic
	// 6.15.8-200.fc42.x86_64 (newer format with additional dot-separated components)
	// So as observed, the kernel value is N.N.N-m or N.N-m or N-m or N.N.N-m.additional.components
	// This implies the len(verStrs) should be at least 1, but can be more than 3

	if len(verStrs) < 1 {
		return semver.Version{}, fmt.Errorf("unable to get kernel version from %q", ver)
	}

	// Take only the first 3 components for semantic version parsing
	// If there are more than 3 components, we'll only use the first 3
	if len(verStrs) > 3 {
		verStrs = verStrs[:3]
	}

	// Given the observations, we use regular expression to extract
	// the patch number from the last element of the verStrs array and
	// append "0" to the verStrs array in case the until its length is
	// 3 as in all cases we want to return from this function :
	// Major.Minor.PatchNumber

	patch := regexp.MustCompilePOSIX(`^[0-9]+`).FindString(verStrs[len(verStrs)-1])
	if patch == "" {
		verStrs[len(verStrs)-1] = "0"
	} else {
		verStrs[len(verStrs)-1] = patch
	}

	for len(verStrs) < 3 {
		verStrs = append(verStrs, "0")
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
