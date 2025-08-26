// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pidfile

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	path = "/tmp/cilium-test-pidfile"
)

func TestWrite(t *testing.T) {
	err := Write(path)
	require.NoError(t, err)
	defer Remove(path)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, content, fmt.Appendf(nil, "%d\n", os.Getpid()))
}

func TestKill(t *testing.T) {
	cmd := exec.Command("sleep", "inf")
	err := cmd.Start()
	require.NoError(t, err)

	err = write(path, cmd.Process.Pid)
	require.NoError(t, err)
	defer Remove(path)

	pid, err := Kill(path)
	require.NoError(t, err)
	require.NotEqual(t, 0, pid)

	err = cmd.Wait()
	require.Error(t, err)
	require.Contains(t, err.Error(), "signal: killed")
}

func TestKillAlreadyFinished(t *testing.T) {
	cmd := exec.Command("sleep", "0")
	err := cmd.Start()
	require.NoError(t, err)

	err = write(path, cmd.Process.Pid)
	require.NoError(t, err)
	defer Remove(path)

	err = cmd.Wait()
	require.NoError(t, err)

	pid, err := Kill(path)
	require.NoError(t, err)
	require.Equal(t, 0, pid)
}

func TestKillPidfileNotExist(t *testing.T) {
	_, err := Kill("/tmp/cilium-foo-bar-some-not-existing-file")
	require.NoError(t, err)
}

func TestKillFailedParsePid(t *testing.T) {
	err := os.WriteFile(path, []byte("foobar\n"), 0644)
	require.NoError(t, err)
	defer Remove(path)

	_, err = Kill(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse pid")
}
