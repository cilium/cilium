// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"

	"github.com/blang/semver/v4"
)

// A binaryCheck checks that a binary called name is installed and optionally
// either exactly expectedVersion, at least version minVersion (inclusive), and
// less than maxVersion (exclusive).
type binaryCheck struct {
	name                string
	command             string
	alternateNames      []string
	ifNotFound          checkResult
	versionArgs         []string
	versionRegexp       *regexp.Regexp
	versionNote         string
	expectedVersion     *semver.Version // exact
	ifUnexpectedVersion checkResult
	minVersion          *semver.Version // inclusive
	maxVersion          *semver.Version // exclusive
	hint                string
}

func (c *binaryCheck) Name() string {
	return c.name
}

func (c *binaryCheck) Run() (checkResult, string) {
	var path string
	command := c.command
	if command == "" {
		command = c.name
	}
	for _, name := range append([]string{command}, c.alternateNames...) {
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
		return checkFailed, fmt.Sprintf("failed to run %s: %s\n%s", path, err, string(output))
	}

	version := output
	if c.versionRegexp != nil {
		match := c.versionRegexp.FindSubmatch(version)
		if len(match) < 2 {
			return checkFailed, fmt.Sprintf("found %s, could not parse version from %s", path, version)
		}
		version = match[1]
	}

	if c.expectedVersion != nil || c.minVersion != nil || c.maxVersion != nil {
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

		if c.minVersion != nil && effectiveVersion.LT(*c.minVersion) {
			return checkError, fmt.Sprintf("found %s, version %s, need at least %s", path, version, c.minVersion)
		}

		if c.maxVersion != nil && effectiveVersion.GTE(*c.maxVersion) {
			return checkError, fmt.Sprintf("found %s, version %s, need less than %s", path, version, c.maxVersion)
		}

		if c.expectedVersion != nil {
			expectedVersion := semver.Version{
				Major: c.expectedVersion.Major,
				Minor: c.expectedVersion.Minor,
				Patch: c.expectedVersion.Patch,
			}
			if effectiveVersion.NE(expectedVersion) {
				result := c.ifUnexpectedVersion
				if result == checkOK {
					result = checkError
				}
				message := fmt.Sprintf("found %s, version %s, expected %s", path, version, expectedVersion)
				if c.versionNote != "" {
					message += "; " + c.versionNote
				}
				return result, message
			}
		}
	}

	message := fmt.Sprintf("found %s, version %s", path, version)
	if c.versionNote != "" {
		message += "; " + c.versionNote
	}
	return checkOK, message
}

func (c *binaryCheck) Hint() string {
	return c.hint
}
