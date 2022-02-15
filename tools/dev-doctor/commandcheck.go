// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os/exec"
)

// A commandCheck checks that a commant runs successfully.
type commandCheck struct {
	name             string
	command          string
	args             []string
	ifFailure        checkResult
	ifSuccessMessage string
	hint             string
}

func (c *commandCheck) Name() string {
	return c.name
}

func (c *commandCheck) Run() (checkResult, string) {
	cmd := exec.Command(c.command, c.args...)
	if err := cmd.Run(); err != nil {
		return c.ifFailure, fmt.Sprintf("%s: %v", cmd, err)
	}
	return checkOK, c.ifSuccessMessage
}

func (c *commandCheck) Hint() string {
	return c.hint
}
