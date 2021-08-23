// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package utils

import (
	"fmt"
	"os/exec"
	"strings"
)

type Logger interface {
	Log(format string, args ...interface{})
}

func Exec(l Logger, command string, args ...string) ([]byte, error) {
	c := exec.Command(command, args...)
	bytes, err := c.CombinedOutput()
	if err != nil {
		cmdStr := fmt.Sprintf("%s %s", command, strings.Join(args, " "))
		l.Log("❌ Unable to execute %q:", cmdStr)
		if len(bytes) > 0 {
			l.Log(" %s", string(bytes))
		}
		return []byte{}, fmt.Errorf("unable to execute %q: %w", cmdStr, err)
	}

	return bytes, err
}
