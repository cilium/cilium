// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package version

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/blang/semver/v4"

	"github.com/cilium/cilium/pkg/versioncheck"
)

// CiliumVersion provides a minimal structure to the version string
type CiliumVersion struct {
	// Version is the semantic version of Cilium
	Version string
	// Revision is the short SHA from the last commit
	Revision string
	// GoRuntimeVersion is the Go version used to run Cilium
	GoRuntimeVersion string
	// Arch is the architecture where Cilium was compiled
	Arch string
	// AuthorDate is the git author time reference stored as string ISO 8601 formatted
	AuthorDate string
}

// ciliumVersion is set to Cilium's version, revision and git author time reference during build.
var ciliumVersion string

// Version is the complete Cilium version string including Go version.
var Version string

func init() {
	// Mimic the output of `go version` and append it to ciliumVersion.
	// Report GOOS/GOARCH of the actual binary, not the system it was built on, in case it was
	// cross-compiled. See #13122
	Version = fmt.Sprintf("%s go version %s %s/%s", ciliumVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// FromString converts a version string into struct
func FromString(versionString string) CiliumVersion {
	// string to parse: "0.13.90 a722bdb 2018-01-09T22:32:37+01:00 go version go1.9 linux/amd64"
	fields := strings.Split(versionString, " ")
	if len(fields) != 7 {
		return CiliumVersion{}
	}

	cver := CiliumVersion{
		Version:          fields[0],
		Revision:         fields[1],
		AuthorDate:       fields[2],
		GoRuntimeVersion: fields[5],
		Arch:             fields[6],
	}
	return cver
}

// GetCiliumVersion returns a initialized CiliumVersion structure
var GetCiliumVersion = sync.OnceValue(func() CiliumVersion {
	return FromString(Version)
})

// Base64 returns the version in a base64 format.
func Base64() (string, error) {
	jsonBytes, err := json.Marshal(Version)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}

// ParseKernelVersion converts a version string to semver.Version.
func ParseKernelVersion(ver string) (semver.Version, error) {
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
