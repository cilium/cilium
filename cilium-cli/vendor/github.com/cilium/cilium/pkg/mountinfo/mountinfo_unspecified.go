// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package mountinfo

import "errors"

const (
	// Dummy FilesystemType superblock magic numbers for filesystems,
	// to be used for IsMountFS.
	FilesystemTypeBPFFS = 0
)

// IsMountFS returns two boolean values, checking
//   - whether the path is a mount point;
//   - if yes, whether its filesystem type is mntType.
//
// Note that this function can not detect bind mounts,
// and is not working properly when path="/".
func IsMountFS(mntType int64, path string) (bool, bool, error) {
	return false, false, errors.New("not implemented")
}
