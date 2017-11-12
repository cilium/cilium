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
	"runtime"
	"strings"
)

// FIXME Write version on a JSON format. Currently a single string:
// `Cilium 0.11.90 774ecd3 Wed, 19 Jul 2017 06:27:28 +0000 go version go1.8.3 linux/amd64`

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
}

var Version string

func versionFrom(versionString string) CiliumVersion {
	cver := CiliumVersion{}
	output := strings.Replace(versionString, "Cilium ", "", 1)

	fields := strings.Split(output, " ")
	cver.Version = fields[0]
	cver.Revision = fields[1]
	cver.Arch = fields[len(fields)-1]
	cver.GoRuntimeVersion = runtime.Version()

	return cver
}

// GetCiliumVersion returns a initialized CiliumVersion structure
func GetCiliumVersion() CiliumVersion {
	return versionFrom(Version)
}

// Base64 returns the version in a base64 format.
func Base64() (string, error) {
	jsonBytes, err := json.Marshal(Version)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}
