// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cgroups

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink/nl"

	"github.com/cilium/cilium/pkg/mountinfo"
)

// mountCgroup mounts the Cgroup v2 filesystem into the desired cgroupRoot directory.
func mountCgroup() error {
	cgroupRootStat, err := os.Stat(cgroupRoot)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(cgroupRoot, 0755); err != nil {
				return fmt.Errorf("Unable to create cgroup mount directory: %s", err)
			}
		} else {
			return fmt.Errorf("Failed to stat the mount path %s: %s", cgroupRoot, err)
		}
	} else if !cgroupRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", cgroupRoot)
	}

	if err := unix.Mount("none", cgroupRoot, "cgroup2", 0, ""); err != nil {
		return fmt.Errorf("failed to mount %s: %s", cgroupRoot, err)
	}

	return nil
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
	b := handle.Bytes()[:8]
	cgID := nl.NativeEndian().Uint64(b)

	return cgID, nil
}
