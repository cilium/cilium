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
	// timeout is deliberately short: TestCombinedOutputFailedTimeout waits it
	// out to exercise the expiry path, so lengthening it slows that test by the
	// same amount.
	timeout = 250 * time.Millisecond

	// runTimeout is used where the command has to actually start before the
	// budget expires. WithTimeout starts its clock at construction, so the
	// budget covers process startup as well as the run; 250ms is exhausted by
	// scheduling delay on a loaded runner, and Start then fails with "context
	// deadline exceeded" instead of the command being killed.
	runTimeout = 2 * time.Second
)

func TestWithTimeout(t *testing.T) {
	cmd := WithTimeout(runTimeout, "sleep", "inf")
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
