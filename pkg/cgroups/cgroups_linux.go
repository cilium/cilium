// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cgroups

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/mountinfo"
)

// mountCgroup mounts the Cgroup v2 filesystem into the desired cgroupRoot directory.
func mountCgroup() error {
	cgroupRootStat, err := os.Stat(cgroupRoot)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(cgroupRoot, 0755); err != nil {
				return fmt.Errorf("Unable to create cgroup mount directory: %w", err)
			}
		} else {
			return fmt.Errorf("Failed to stat the mount path %s: %w", cgroupRoot, err)
		}
	} else if !cgroupRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", cgroupRoot)
	}

	infos, err := mountinfo.GetMountInfo()
	if err != nil {
		return err
	}
	if err := unix.Mount("none", cgroupRoot, "cgroup2", 0, cgroup2RootFlags(infos)); err != nil {
		return fmt.Errorf("failed to mount %s: %w", cgroupRoot, err)
	}

	return nil
}

func cgroup2RootFlags(infos []*mountinfo.MountInfo) string {
	for _, info := range infos {
		if info.FilesystemType != "cgroup2" {
			continue
		}
		var flags []string
		for opt := range strings.SplitSeq(info.SuperOptions, ",") {
			if opt != "" && opt != "rw" && opt != "ro" {
				flags = append(flags, opt)
			}
		}
		return strings.Join(flags, ",")
	}
	return ""
}

// checkOrMountCustomLocation tries to check or mount the cgroup filesystem in the
// given path.
func cgrpCheckOrMountLocation(cgroupRoot string) error {
	setCgroupRoot(cgroupRoot)

	// Check whether the custom location has a mount.
	mounted, cgroupInstance, err := mountinfo.IsMountFS(mountinfo.FilesystemTypeCgroup2, cgroupRoot)
	if err != nil {
		return err
	}

	// If the custom location has no mount, let's mount there.
	if !mounted {
		return mountCgroup()
	} else if !cgroupInstance {
		return fmt.Errorf("Mount in the custom directory %s has a different filesystem than cgroup2", cgroupRoot)
	}

	return nil
}

func GetCgroupID(cgroupPath string) (uint64, error) {
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, cgroupPath, 0)
	if err != nil {
		return 0, fmt.Errorf("NameToHandleAt failed: %w", err)
	}
	b := handle.Bytes()
	if len(b) < 8 {
		return 0, fmt.Errorf("handle returned by NameToHandleAt is too small (%v bytes)", len(b))
	}
	return binary.NativeEndian.Uint64(b[:8]), nil
}
