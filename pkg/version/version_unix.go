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
	verStrs := strings.Split(ver, ".")

	// We used to assume kernel versions will follow a specific format. However,
	// different distributions change this. The only assumption we can really make
	// is that there should be at least one digit.

	if len(verStrs) < 1 {
		return semver.Version{}, fmt.Errorf("unable to get kernel version from %q", ver)
	}

	// Use regular expression to extract the patch number from the last element of
	// the verStrs array, appending "0" to the verStrs array if we get something odd
	// like a string.

	patch := regexp.MustCompilePOSIX(`^[0-9]+`).FindString(verStrs[len(verStrs)-1])
	if patch == "" {
		verStrs[len(verStrs)-1] = "0"
	} else {
		verStrs[len(verStrs)-1] = patch
	}

	// Append another zero if the number of parts to verStrs still does not provide
	// a specific Major.Minor.Patch scheme. Anything beyond this is truncated.

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
