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
	"strings"
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

// Version is set during build
var Version string

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
