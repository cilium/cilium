// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
