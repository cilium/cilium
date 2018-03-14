// Copyright 2018 Authors of Cilium
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

package bpf

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"golang.org/x/sys/unix"
)

var (
	// Path to where cgroup2 is mounted (default: /mnt/cilium-cgroup2)
	cgroup2 = "/mnt/cilium-cgroup2"
)

func SetCgroupPath(path string) {
	cgroup2 = path
}

func GetCgroupPath() string {
	return cgroup2
}

var (
	mountCgrpOnce  sync.Once
	mountCgrpMutex lock.Mutex
	mountedCgrp    bool
)

func mountCgroup2() error {
	mountCgrpMutex.Lock()
	// Mount cgroupv2 at cgroup2 mount point
	args := []string{"-q", cgroup2}
	_, err := exec.Command("mountpoint", args...).CombinedOutput()
	if err != nil {
		args = []string{"none", cgroup2, "-t", "cgroup2"}
		out, err := exec.Command("mount", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("command execution failed: %s\n%s", err, out)
		}
	} else { // Already mounted. We need to fail if mounted multiple times.
		log.Infof("")
	}

	var fsdata unix.Statfs_t
	if err := unix.Statfs(cgroup2, &fsdata); err != nil {
		return fmt.Errorf("BPF cgroup2 path %s is not mounted", cgroup2)
	}

	// This is the value of cgroupv2 defined in uapi/linux/magic.h
	magic := uint32(0x63677270)
	if uint32(fsdata.Type) != magic {
		log.WithField(logfields.Path, cgroup2).Warningf("BPF root is not a cgroupv2 filesystem (%#x != %#x)",
			uint32(fsdata.Type), magic)
	}

	mounted = true
	mountCgrpMutex.Unlock()
	return nil
}

// MountCgroup2 mounts the cgroupV2 filesystem
func MountCgroup2() {
	mountCgrpOnce.Do(func() {
		if err := mountCgroup2(); err != nil {
			log.WithError(err).Fatal("Unable to mount CgroupV2 filesystem")
		}

		log.Infof("Mounted CgroupV2 filesystem %s", cgroup2)
	})
}

// UnMountFS unmounts the BPF filesystem.
func UnMountCgroup2() error {
	mountCgrpMutex.Lock()
	defer mountCgrpMutex.Unlock()

	if err := syscall.Unmount(GetCgroupPath(), syscall.MNT_DETACH); err != nil {
		return err
	}

	mountedCgrp = false

	return nil
}
