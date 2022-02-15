// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bytes"
	"os/exec"
	"regexp"
)

var linuxRegexp = regexp.MustCompile(`(?i)linux`)

// A unameCheck checks the output of uname -a.
type unameCheck struct{}

func (unameCheck) Name() string {
	return "uname"
}

func (unameCheck) Run() (checkResult, string) {
	output, err := exec.Command("uname", "-a").CombinedOutput()
	if err != nil {
		return checkFailed, err.Error()
	}

	message := string(bytes.TrimSpace(output))
	if !linuxRegexp.Match(output) {
		return checkWarning, message
	}

	return checkOK, message
}

func (unameCheck) Hint() string {
	return ""
}
