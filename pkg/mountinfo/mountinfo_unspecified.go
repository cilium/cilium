// Copyright 2021 Authors of Cilium
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

// +build !linux

package mountinfo

import "errors"

const (
	// Dummy FilesystemType superblock magic numbers for filesystems,
	// to be used for IsMountFS.
	FilesystemTypeBPFFS = 0
)

// IsMountFS returns two boolean values, checking
//  - whether the path is a mount point;
//  - if yes, whether its filesystem type is mntType.
//
// Note that this function can not detect bind mounts,
// and is not working properly when path="/".
func IsMountFS(mntType int64, path string) (bool, bool, error) {
	return false, false, errors.New("not implemented")
}
