/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package version provides the version of the main module.
package version

import (
	"fmt"
	"runtime/debug"
)

// Version returns the version of the main module
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil || info.Main.Version == "" {
		// binary has not been built with module support or doesn't contain a version.
		return "(unknown)"
	}
	return info.Main.Version
}

// Print prints the main module version on stdout.
//
// Print will display either:
//
// - "Version: v0.2.1" when the program has been compiled with:
//
//	$ go get github.com/controller-tools/cmd/controller-gen@v0.2.1
//
//	Note: go modules requires the usage of semver compatible tags starting with
//	     'v' to have nice human-readable versions.
//
// - "Version: (devel)" when the program is compiled from a local git checkout.
//
// - "Version: (unknown)" when not using go modules.
func Print() {
	fmt.Printf("Version: %s\n", Version())
}
