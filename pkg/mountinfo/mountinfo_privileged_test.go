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

// +build privileged_tests

package mountinfo

import (
	"io/ioutil"
	"os"

	"golang.org/x/sys/unix"

	. "gopkg.in/check.v1"
)

type MountInfoPrivilegedTestSuite struct{}

var _ = Suite(&MountInfoPrivilegedTestSuite{})

// TestIsMountFSbyMount tests the public function IsMountFS by performing
// an actual mount.
func (s *MountInfoPrivilegedTestSuite) TestIsMountFSbyMount(c *C) {
	tmpDir, err := ioutil.TempDir("", "IsMountFS_")
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
