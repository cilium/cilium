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
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// An iptablesRuleCheck checks that the given iptables rule is present.
type iptablesRuleCheck struct {
	rule []string
}

func (c *iptablesRuleCheck) Name() string {
	return "iptables-rule"
}

func (c *iptablesRuleCheck) Run() (checkResult, string) {
	if runtime.GOOS != "linux" {
		return checkSkipped, "iptables only used on linux"
	}

	iptablesPath, err := exec.LookPath("iptables")
	if errors.Is(err, exec.ErrNotFound) {
		return checkSkipped, "iptables not found in $PATH"
	}

	cmd := exec.Command(iptablesPath, append([]string{"--check"}, []string(c.rule)...)...)
	if os.Getuid() != 0 {
		var err error
		cmd, err = sudo(cmd)
		if err != nil {
			return checkFailed, err.Error()
		}
	}
	err = cmd.Run()
	if _, ok := err.(*exec.ExitError); err != nil && !ok {
		return checkFailed, err.Error()
	}
	if cmd.ProcessState.ExitCode() != 0 {
		return checkError, fmt.Sprintf("rule %s not found", strings.Join(c.rule, " "))
	}

	return checkOK, fmt.Sprintf("found rule %s", strings.Join(c.rule, " "))
}

func (c *iptablesRuleCheck) Hint() string {
	return fmt.Sprintf(`Run "sudo iptables -A %s".`, strings.Join(c.rule, " "))
}
