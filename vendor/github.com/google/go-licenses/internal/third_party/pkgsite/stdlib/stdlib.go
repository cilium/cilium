// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stdlib supports special handling of the Go standard library.
// Regardless of the how the standard library has been split into modules for
// development and testing, the discovery site treats it as a single module
// named "std".
package stdlib

import (
	"fmt"
	"strings"

	"github.com/google/go-licenses/internal/third_party/pkgsite/derrors"
	"github.com/google/go-licenses/internal/third_party/pkgsite/version"
	"golang.org/x/mod/semver"
)

const (
	// ModulePath is the name of the module for the standard library.
	ModulePath = "std"

	// DevFuzz is the branch name for fuzzing in beta.
	DevFuzz = "dev.fuzz"

	// DevBoringCrypto is the branch name for dev.boringcrypto.
	DevBoringCrypto = "dev.boringcrypto"
)

// SupportedBranches are the branches of the stdlib repo supported by pkgsite.
var SupportedBranches = map[string]bool{
	version.Master:  true,
	DevBoringCrypto: true,
	DevFuzz:         true,
}

// TagForVersion returns the Go standard library repository tag corresponding
// to semver. The Go tags differ from standard semantic versions in a few ways,
// such as beginning with "go" instead of "v".
func TagForVersion(v string) (_ string, err error) {
	defer derrors.Wrap(&err, "TagForVersion(%q)", v)

	// Special case: master => master or dev.fuzz => dev.fuzz
	if SupportedBranches[v] {
		return v, nil
	}
	if strings.HasPrefix(v, "v0.0.0") {
		return version.Master, nil
	}
	// Special case: v1.0.0 => go1.
	if v == "v1.0.0" {
		return "go1", nil
	}
	if !semver.IsValid(v) {
		return "", fmt.Errorf("%w: requested version is not a valid semantic version: %q ", derrors.InvalidArgument, v)
	}
	goVersion := semver.Canonical(v)
	prerelease := semver.Prerelease(goVersion)
	versionWithoutPrerelease := strings.TrimSuffix(goVersion, prerelease)
	patch := strings.TrimPrefix(versionWithoutPrerelease, semver.MajorMinor(goVersion)+".")
	if patch == "0" {
		versionWithoutPrerelease = strings.TrimSuffix(versionWithoutPrerelease, ".0")
	}
	goVersion = fmt.Sprintf("go%s", strings.TrimPrefix(versionWithoutPrerelease, "v"))
	if prerelease != "" {
		// Go prereleases look like  "beta1" instead of "beta.1".
		// "beta1" is bad for sorting (since beta10 comes before beta9), so
		// require the dot form.
		i := finalDigitsIndex(prerelease)
		if i >= 1 {
			if prerelease[i-1] != '.' {
				return "", fmt.Errorf("%w: final digits in a prerelease must follow a period", derrors.InvalidArgument)
			}
			// Remove the dot.
			prerelease = prerelease[:i-1] + prerelease[i:]
		}
		goVersion += strings.TrimPrefix(prerelease, "-")
	}
	return goVersion, nil
}

// finalDigitsIndex returns the index of the first digit in the sequence of digits ending s.
// If s doesn't end in digits, it returns -1.
func finalDigitsIndex(s string) int {
	// Assume ASCII (since the semver package does anyway).
	var i int
	for i = len(s) - 1; i >= 0; i-- {
		if s[i] < '0' || s[i] > '9' {
			break
		}
	}
	if i == len(s)-1 {
		return -1
	}
	return i + 1
}

const (
	GoSourceRepoURL = "https://cs.opensource.google/go/go"
)

// Directory returns the directory of the standard library relative to the repo root.
func Directory(v string) string {
	if semver.Compare(v, "v1.4.0-beta.1") >= 0 ||
		SupportedBranches[v] || strings.HasPrefix(v, "v0.0.0") {
		return "src"
	}
	// For versions older than v1.4.0-beta.1, the stdlib is in src/pkg.
	return "src/pkg"
}
