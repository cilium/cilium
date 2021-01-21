// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package version

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"github.com/cilium/cilium/pkg/versioncheck"

	go_version "github.com/blang/semver"
	"golang.org/x/sys/unix"
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
func GetCiliumVersion() CiliumVersion {
	return FromString(Version)
}

// Base64 returns the version in a base64 format.
func Base64() (string, error) {
	jsonBytes, err := json.Marshal(Version)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}

func parseKernelVersion(ver string) (go_version.Version, error) {
	verStrs := strings.Split(ver, ".")
	switch {
	case len(verStrs) < 2:
		return go_version.Version{}, fmt.Errorf("unable to get kernel version from %q", ver)
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
func GetKernelVersion() (go_version.Version, error) {
	var unameBuf unix.Utsname
	if err := unix.Uname(&unameBuf); err != nil {
		return go_version.Version{}, err
	}
	return parseKernelVersion(string(unameBuf.Release[:]))
}
