// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mountinfo

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	// FilesystemType superblock magic numbers for filesystems,
	// to be used for IsMountFS.
	FilesystemTypeBPFFS   = unix.BPF_FS_MAGIC
	FilesystemTypeCgroup2 = unix.CGROUP2_SUPER_MAGIC
)

// IsMountFS returns two boolean values, checking
//   - whether the path is a mount point;
//   - if yes, whether its filesystem type is mntType.
//
// Note that this function can not detect bind mounts,
// and is not working properly when path="/".
func IsMountFS(mntType int64, path string) (bool, bool, error) {
	var st, pst unix.Stat_t

	err := unix.Lstat(path, &st)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			// non-existent path can't be a mount point
			return false, false, nil
		}
		return false, false, &os.PathError{Op: "lstat", Path: path, Err: err}
	}

	parent := filepath.Dir(path)
	err = unix.Lstat(parent, &pst)
	if err != nil {
		return false, false, &os.PathError{Op: "lstat", Path: parent, Err: err}
	}
	if st.Dev == pst.Dev {
		// parent has the same dev -- not a mount point
		return false, false, nil
	}

	// Check the fstype
	fst := unix.Statfs_t{}
	err = unix.Statfs(path, &fst)
	if err != nil {
		return true, false, &os.PathError{Op: "statfs", Path: path, Err: err}
	}

	return true, fst.Type == mntType, nil

}
