// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exec

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

const (
	timeout = 250 * time.Millisecond
)

func TestWithTimeout(t *testing.T) {
	cmd := WithTimeout(timeout, "sleep", "inf")
	err := cmd.Start()
	require.NoError(t, err)
	err = cmd.Wait()
	require.Error(t, err)
	require.Contains(t, err.Error(), "signal: killed")
}

func TestWithCancel(t *testing.T) {
	cmd, cancel := WithCancel(context.Background(), "sleep", "inf")
	require.NotNil(t, cancel)
	err := cmd.Start()
	require.NoError(t, err)
	cancel()
}

func TestCanceled(t *testing.T) {
	logger := hivetest.Logger(t)
	cmd, cancel := WithCancel(context.Background(), "sleep", "inf")
	require.NotNil(t, cancel)
	cancel()
	_, err := cmd.CombinedOutput(logger, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "context canceled")
}

func TestCombinedOutput(t *testing.T) {
	logger := hivetest.Logger(t)
	cmd := CommandContext(context.Background(), "echo", "foo")
	out, err := cmd.CombinedOutput(logger, true)
	require.NoError(t, err)
	require.Equal(t, "foo\n", string(out))
}

func TestCombinedOutputFailedTimeout(t *testing.T) {
	logger := hivetest.Logger(t)
	cmd := WithTimeout(timeout, "sleep", "inf")
	time.Sleep(timeout)
	_, err := cmd.CombinedOutput(logger, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "context deadline exceeded")
}
