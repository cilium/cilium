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

package cgroups

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mountinfo"
	"github.com/cilium/cilium/pkg/warnings"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
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

// cgrpSanityCheck performs a sanity check on the mounted cgroup fs and issues
// a warning if something seems wrong.
//
// It does this by recursively checking the number of pids in "cgroup.procs".
// If the total number is 1, it is likely that the cgroup used is incorrect.
func cgrpSanityCheck() {

	procCount := 0
	err := filepath.Walk(cgroupRoot, func(path string, info fs.FileInfo, _ error) error {
		if info.IsDir() {
			return nil
		}

		if info.Name() != "cgroup.procs" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			procCount++
			if procCount > 1 {
				return errors.New("")
			}
		}
		return nil
	})

	// if error is not set, it means that we did not reach the desired number of processes
	if err == nil {
		log.WithFields(logrus.Fields{
			logfields.URL:        warnings.GetUrl("cgrouplowproccount"),
			logfields.CgroupPath: cgroupRoot,
			"process-count":      procCount,
		}).Warn("Process count under cgroup is unexpectedly low")
	}
}

// checkOrMountCustomLocation tries to check or mount the BPF filesystem in the
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
		if err := mountCgroup(); err != nil {
			return err
		}
	}

	if !cgroupInstance {
		return fmt.Errorf("Mount in the custom directory %s has a different filesystem than cgroup2", cgroupRoot)
	}

	return nil
}
