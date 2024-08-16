// Copyright 2018 Authors of Cilium
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

// Package versioncheck provides utility wrappers for go-version, allowing the
// constraints to be used as global variables.
package versioncheck

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/blang/semver/v4"
)

// MustCompile wraps go-version.NewConstraint, panicing when an error is
// returns (this occurs when the constraint cannot be parsed).
// It is intended to be use similar to re.MustCompile, to ensure unparseable
// constraints are caught in testing.
func MustCompile(constraint string) semver.Range {
	verCheck, err := Compile(constraint)
	if err != nil {
		panic(fmt.Errorf("cannot compile go-version constraint '%s' %s", constraint, err))
	}
	return verCheck
}

// Compile trivially wraps go-version.NewConstraint, returning the constraint
// and error
func Compile(constraint string) (semver.Range, error) {
	return semver.ParseRange(constraint)
}

// MustVersion wraps go-version.NewVersion, panicing when an error is
// returns (this occurs when the version cannot be parsed).
func MustVersion(version string) semver.Version {
	ver, err := Version(version)
	if err != nil {
		panic(fmt.Errorf("cannot compile go-version version '%s' %s", version, err))
	}
	return ver
}

// Version wraps go-version.NewVersion, panicing when an error is
// returns (this occurs when the version cannot be parsed).
func Version(version string) (semver.Version, error) {
	ver, err := semver.ParseTolerant(version)
	if err != nil {
		return ver, err
	}

	if len(ver.Pre) == 0 {
		return ver, nil
	}

	for _, pre := range ver.Pre {
		if strings.Contains(pre.VersionStr, "rc") ||
			strings.Contains(pre.VersionStr, "beta") ||
			strings.Contains(pre.VersionStr, "alpha") {

			return ver, nil
		}
	}

	strSegments := make([]string, 3)
	strSegments[0] = strconv.Itoa(int(ver.Major))
	strSegments[1] = strconv.Itoa(int(ver.Minor))
	strSegments[2] = strconv.Itoa(int(ver.Patch))
	verStr := strings.Join(strSegments, ".")
	return semver.ParseTolerant(verStr)
}
