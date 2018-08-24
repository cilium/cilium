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
	"os"
	"os/exec"
	"sync"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/mountinfo"
)

var (
	// Path to where cgroup is mounted
	cgroupRoot = defaults.DefaultCgroupRoot

	// Set to true on first get request to detect misorder
	cgrpLockedDown = false

	// Only mount a single instance
	cgrpMountOnce sync.Once
)

func cgrpLockDown() {
	cgrpLockedDown = true
}

func SetCgroupRoot(path string) {
	if cgrpLockedDown {
		panic("SetCgroupRoot() called after cgroup mounted")
	}
	cgroupRoot = path
}

func GetCgroupRoot() string {
	once.Do(cgrpLockDown)
	return cgroupRoot
}

// mountCgroup mounts the Cgroup v2 filesystem into the desired cgroupRoot directory.
func mountCgroup() error {
	prog := "mount"
	cgroupRootStat, err := os.Stat(cgroupRoot)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(cgroupRoot, 0755); err != nil {
				return fmt.Errorf("unable to create bpf mount directory: %s", err)
			}
		} else {
			return fmt.Errorf("failed to stat the mount path %s: %s", mapRoot, err)
		}
	} else if !cgroupRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", cgroupRoot)
	}

	mnt_args := []string{"-t", "cgroup2", "none", cgroupRoot}
	_, err = exec.Command(prog, mnt_args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to mount %s: %s", cgroupRoot, err)
	}
	cgrpLockDown()
	return nil
}

// checkOrMountCustomLocation tries to check or mount the BPF filesystem in the
// given path.
func cgrpCheckOrMountLocation(cgroupRoot string) error {
	SetCgroupRoot(cgroupRoot)

	// Check whether the custom location has a mount.
	mounted, cgroupInstance, err := mountinfo.IsMountFS(mountinfo.FilesystemTypeCgroup2, cgroupRoot)
	if err != nil {
		return err
	}

	// If the custom location has no mount, let's mount there.
	if !mounted {
		if err := mountCgroup(); err != nil {
			return err
		}
	}

	if !cgroupInstance {
		return fmt.Errorf("mount in the custom directory %s has a different filesystem than cgroup2", cgroupRoot)
	}
	return nil
}

func CheckOrMountCgrpFS(mapRoot string) {
	cgrpMountOnce.Do(func() {
		if mapRoot == "" {
			mapRoot = cgroupRoot
		}
		err := cgrpCheckOrMountLocation(mapRoot)
		// Failed cgroup2 mount is not a fatal error, sockmap will be disabled however
		if err == nil {
			log.Infof("Mounted Cgroup2 filesystem %s", mapRoot)
		}
	})
}
