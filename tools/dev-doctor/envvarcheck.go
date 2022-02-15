// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"
	"strings"
)

// An envVarCheck checks that an environment variable is set and not empty.
type envVarCheck struct {
	name            string
	ifNotSetOrEmpty checkResult
}

func (c *envVarCheck) Name() string {
	name := c.name
	name = strings.ToLower(name)
	name = strings.Replace(name, "_", "-", -1)
	return name
}

func (c *envVarCheck) Run() (checkResult, string) {
	if os.Getenv(c.name) == "" {
		return c.ifNotSetOrEmpty, fmt.Sprintf("$%s not set or empty", c.name)
	}
	return checkOK, fmt.Sprintf("$%s is set", c.name)
}

func (c *envVarCheck) Hint() string {
	return ""
}
