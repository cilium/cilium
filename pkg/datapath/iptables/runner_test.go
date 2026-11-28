// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

// TestRunnerExitError checks the Runner contract that callers rely on to tell
// "rule or chain not found" (exit status 1) apart from other failures.
func TestRunnerExitError(t *testing.T) {
	logger := hivetest.Logger(t)
	r := runner{
		ip4tables: &ipt{logger: logger, prog: "false"},
		ip6tables: &ipt{logger: logger, prog: "true"},
	}

	_, err := r.RunIPv4("-t", "nat", "-S", "FOO")
	exitErr, ok := errors.AsType[*exec.ExitError](err)
	require.True(t, ok, "error should wrap *exec.ExitError, got %v", err)
	require.Equal(t, 1, exitErr.ExitCode())

	_, err = r.RunIPv6("-t", "nat", "-S", "FOO")
	require.NoError(t, err)
}
