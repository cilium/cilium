// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

//go:build linux && privileged_tests
// +build linux,privileged_tests

package mountinfo

import (
	"os"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

type MountInfoPrivilegedTestSuite struct{}

var _ = Suite(&MountInfoPrivilegedTestSuite{})

// TestIsMountFSbyMount tests the public function IsMountFS by performing
// an actual mount.
func (s *MountInfoPrivilegedTestSuite) TestIsMountFSbyMount(c *C) {
	tmpDir, err := os.MkdirTemp("", "IsMountFS_")
	c.Assert(err, IsNil)
	defer os.RemoveAll(tmpDir)

	mounted, matched, err := IsMountFS(unix.TMPFS_MAGIC, tmpDir)
	c.Assert(err, IsNil)
	c.Assert(mounted, Equals, false)
	c.Assert(matched, Equals, false)

	err = unix.Mount("tmpfs", tmpDir, "tmpfs", 0, "")
	c.Assert(err, IsNil)
	defer unix.Unmount(tmpDir, unix.MNT_DETACH)

	// deliberately check with wrong fstype
	mounted, matched, err = IsMountFS(unix.PROC_SUPER_MAGIC, tmpDir)
	c.Assert(err, IsNil)
	c.Assert(mounted, Equals, true)
	c.Assert(matched, Equals, false)

	// now check with proper fstype
	mounted, matched, err = IsMountFS(unix.TMPFS_MAGIC, tmpDir)
	c.Assert(err, IsNil)
	c.Assert(mounted, Equals, true)
	c.Assert(matched, Equals, true)
}
