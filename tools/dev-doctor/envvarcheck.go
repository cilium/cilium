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
