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

	// We are assuming the kernel version will be one of the following:
	// 4.9.17-040917-generic or 4.9-040917-generic or 4-generic
	// So as observed, the kernel value is N.N.N-m or N.N-m or N-m
	// This implies the len(verStrs) should be between 1 and 3

	if len(verStrs) < 1 || len(verStrs) > 3 {
		return semver.Version{}, fmt.Errorf("unable to get kernel version from %q", ver)
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
