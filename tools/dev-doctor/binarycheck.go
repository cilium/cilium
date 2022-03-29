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

// A binaryCheck checks that a binary called name is installed and optionally at
// least version minVersion (inclusive), and less than maxVersion (exclusive)
type binaryCheck struct {
	name           string
	command        string
	alternateNames []string
	ifNotFound     checkResult
	versionArgs    []string
	versionRegexp  *regexp.Regexp
	minVersion     *semver.Version // inclusive
	maxVersion     *semver.Version // exclusive
	hint           string
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

	if c.minVersion != nil || c.maxVersion != nil {
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
	}

	return checkOK, fmt.Sprintf("found %s, version %s", path, version)
}

func (c *binaryCheck) Hint() string {
	return c.hint
}
