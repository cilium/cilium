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

	"github.com/blang/semver/v4"
)

// A binaryCheck checks that a binary called name is installed and optionally at
// least version minVersion.
type binaryCheck struct {
	name           string
	alternateNames []string
	ifNotFound     checkResult
	versionArgs    []string
	versionRegexp  *regexp.Regexp
	minVersion     *semver.Version
	hint           string
}

func (c *binaryCheck) Name() string {
	return c.name
}

func (c *binaryCheck) Run() (checkResult, string) {
	var path string
	for _, name := range append([]string{c.name}, c.alternateNames...) {
		var err error
		path, err = exec.LookPath(name)
		switch {
		case errors.Is(err, exec.ErrNotFound):
			continue
		case err != nil:
			return checkFailed, err.Error()
		}
	}
	if path == "" {
		return c.ifNotFound, fmt.Sprintf("%s not found in $PATH", c.name)
	}

	if c.versionArgs == nil {
		return checkOK, fmt.Sprintf("found %s", path)
	}

	output, err := exec.Command(path, c.versionArgs...).CombinedOutput()
	if err != nil {
		return checkFailed, err.Error()
	}

	version := output
	if c.versionRegexp != nil {
		match := c.versionRegexp.FindSubmatch(version)
		if len(match) != 2 {
			return checkFailed, fmt.Sprintf("found %s, could not parse version from %s", path, version)
		}
		version = match[1]
	}

	if c.minVersion != nil {
		v, err := semver.ParseTolerant(string(version))
		if err != nil {
			return checkFailed, err.Error()
		}

		// only compare the major, minor, and patch versions. this is because
		// github.com/blang/semver treats any extra text is a pre-release
		// version, meaning that, e.g. clang version "10.0.0-4ubuntu1" compares
		// less than "10.0.0"
		effectiveVersion := semver.Version{
			Major: v.Major,
			Minor: v.Minor,
			Patch: v.Patch,
		}
		if effectiveVersion.LT(*c.minVersion) {
			return checkError, fmt.Sprintf("found %s, version %s, need %s", path, version, c.minVersion)
		}
	}

	return checkOK, fmt.Sprintf("found %s, version %s", path, version)
}

func (c *binaryCheck) Hint() string {
	return c.hint
}
