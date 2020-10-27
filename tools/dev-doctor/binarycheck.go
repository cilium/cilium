// Copyright 2020 Authors of Cilium
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

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"

	"github.com/blang/semver"
)

// A binaryCheck checks that a binary called name is installed and optionally at
// least version minVersion.
type binaryCheck struct {
	name          string
	ifNotFound    checkResult
	versionArgs   []string
	versionRegexp *regexp.Regexp
	minVersion    *semver.Version
	hint          string
}

func (c *binaryCheck) Name() string {
	return c.name
}

func (c *binaryCheck) Run() (checkResult, string) {
	path, err := exec.LookPath(c.name)
	switch {
	case errors.Is(err, exec.ErrNotFound):
		return c.ifNotFound, fmt.Sprintf("%s not found in $PATH", c.name)
	case err != nil:
		return checkFailed, err.Error()
	}

	if c.versionArgs == nil {
		return checkOK, fmt.Sprintf("found %s", path)
	}

	output, err := exec.Command(path, c.versionArgs...).CombinedOutput()
	if err != nil {
		return checkFailed, err.Error()
	}

	versionBytes := output
	if c.versionRegexp != nil {
		match := c.versionRegexp.FindSubmatch(versionBytes)
		if len(match) != 2 {
			return checkFailed, fmt.Sprintf("found %s, could not parse version from %s", path, versionBytes)
		}
		versionBytes = match[1]
	}
	version, err := semver.ParseTolerant(string(versionBytes))
	if err != nil {
		return checkFailed, err.Error()
	}

	// Only compare the major, minor, and patch versions. This is because
	// github.com/blang/semver treats any extra text is a pre-release version,
	// meaning that 10.0.0-4ubuntu1 compares less than 10.0.0.
	effectiveVersion := semver.Version{
		Major: version.Major,
		Minor: version.Minor,
		Patch: version.Patch,
	}
	if c.minVersion != nil && effectiveVersion.LT(*c.minVersion) {
		return checkError, fmt.Sprintf("found %s, version %s, need %s", path, version, c.minVersion)
	}

	return checkOK, fmt.Sprintf("found %s, version %s", path, version)
}

func (c *binaryCheck) Hint() string {
	return c.hint
}
