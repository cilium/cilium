// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package mountinfo

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/testutils"
)

// TestIsMountFSbyMount tests the public function IsMountFS by performing
// an actual mount.
func TestIsMountFSbyMount(t *testing.T) {
	testutils.PrivilegedTest(t)

	tmpDir, err := os.MkdirTemp("", "IsMountFS_")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mounted, matched, err := IsMountFS(unix.TMPFS_MAGIC, tmpDir)
	require.NoError(t, err)
	require.False(t, mounted)
	require.False(t, matched)

	err = unix.Mount("tmpfs", tmpDir, "tmpfs", 0, "")
	require.NoError(t, err)
	defer unix.Unmount(tmpDir, unix.MNT_DETACH)

	// deliberately check with wrong fstype
	mounted, matched, err = IsMountFS(unix.PROC_SUPER_MAGIC, tmpDir)
	require.NoError(t, err)
	require.True(t, mounted)
	require.False(t, matched)

	// now check with proper fstype
	mounted, matched, err = IsMountFS(unix.TMPFS_MAGIC, tmpDir)
	require.NoError(t, err)
	require.True(t, mounted)
	require.True(t, matched)
}
