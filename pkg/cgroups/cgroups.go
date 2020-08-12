// Copyright 2018-2020 Authors of Cilium
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
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mountinfo"

	"golang.org/x/sys/unix"
)

var (
	// Path to where cgroup is mounted
	cgroupRoot = defaults.DefaultCgroupRoot

	// Only mount a single instance
	cgrpMountOnce sync.Once

	// Only query cgroup mounts once
	cgrpQueryOnce sync.Once

	// cgroupNetMounts is a map from net_cls/net_prio mount to mount path
	cgroupNetMounts = make(map[string]string)
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cgroups")

// setCgroupRoot will set the path to mount cgroupv{1,2}
func setCgroupRoot(path string) {
	cgroupRoot = path
}

// GetCgroupRoot returns the base path for the cgroupv{1,2} mount. The fs'es
// are under the subdir v1 or v2 corresponding to their type.
func GetCgroupRoot() string {
	return cgroupRoot
}

func GetCgroupRootV1() string {
	return fmt.Sprintf("%sv1", cgroupRoot)
}

func GetCgroupRootV2() string {
	return fmt.Sprintf("%sv2", cgroupRoot)
}

func mountDirSetup(base string) error {
	cgroupRootStat, err := os.Stat(base)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(base, 0755); err != nil {
				return fmt.Errorf("Unable to create cgroup mount directory: %s", err)
			}
		} else {
			return fmt.Errorf("Failed to stat the mount path %s: %s", base, err)
		}
	} else if !cgroupRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", base)
	}
	return nil
}

// mountCgroup mounts the Cgroup v{1,2} filesystem into the desired cgroupRoot directory.
func mountCgroup() error {
	v1Mount := fmt.Sprintf("%sv1", cgroupRoot)
	v2Mount := fmt.Sprintf("%sv2", cgroupRoot)

	if err := mountDirSetup(v1Mount); err != nil {
		return err
	}
	if err := mountDirSetup(v2Mount); err != nil {
		return err
	}
	if err := unix.Mount("none", v1Mount, "cgroup", 0, "net_cls,net_prio"); err != nil {
		return fmt.Errorf("failed to mount %s: %s", v1Mount, err)
	}
	if err := unix.Mount("none", v2Mount, "cgroup2", 0, ""); err != nil {
		return fmt.Errorf("failed to mount %s: %s", v2Mount, err)
	}

	return nil
}

// checkOrMountCustomLocation tries to check or mount the BPF filesystem in the
// given path.
func cgrpCheckOrMountLocation(cgroupRoot string) error {
	v1Mount := fmt.Sprintf("%sv1", cgroupRoot)
	v2Mount := fmt.Sprintf("%sv2", cgroupRoot)

	setCgroupRoot(cgroupRoot)
Retry:
	v1Mounted, v1CgroupInstance, err1 := mountinfo.IsMountFS(mountinfo.FilesystemTypeCgroup1, v1Mount)
	v2Mounted, v2CgroupInstance, err2 := mountinfo.IsMountFS(mountinfo.FilesystemTypeCgroup2, v2Mount)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("Cannot retrieve IsMountFS info from %s", cgroupRoot)
	}
	if !v1Mounted || !v2Mounted {
		if err := mountCgroup(); err != nil {
			return err
		}
		goto Retry
	}
	if !v1CgroupInstance || !v2CgroupInstance {
		return fmt.Errorf("Mount in the custom directory %s has a different filesystem than cgroup{1,2}", cgroupRoot)
	}
	return nil
}

// CheckOrMountCgrpFS this checks if the cilium cgroup{v1,v2} root mount point
// is mounted and if not mounts it. If mapRoot is "" it will mount the default
// location. It is harmless to have multiple cgroup{v1,v2} root mounts so unlike
// BPFFS case we simply mount at the cilium default regardless if the system
// has another mount created by systemd or otherwise.
func CheckOrMountCgrpFS(mapRoot string) {
	cgrpMountOnce.Do(func() {
		if mapRoot == "" {
			mapRoot = cgroupRoot
		}
		err := cgrpCheckOrMountLocation(mapRoot)
		if err == nil {
			log.Infof("Mounted cgroup{v1,v2} filesystems at %s{v1,v2}/", mapRoot)
		} else {
			log.WithError(err).Fatalf("Mounting cgroup{v1,v2} filesystems at %s failed", mapRoot)
		}
	})
}

// getCgroupNetMounts returns a map of cgroup v1 net type to mount path:
//
// net_cls -> /path/to/net_cls
// net_cls,net_prio -> /path/to/net_cls,net_prio
// net_prio -> /path/to/net_prio
func getCgroupNetMounts() map[string]string {
	cgrpQueryOnce.Do(func() {
		mounts, err := mountinfo.GetMountInfo()
		if err != nil {
			log.WithError(err).Warningf("Unable to detect cgroup filesystem mounts")
			return
		}

		for _, mount := range mounts {
			if mount.FilesystemType != "cgroup" {
				continue
			}

			opts := strings.Split(mount.SuperOptions, ",")
			cgroupTypes := ""
			for _, o := range opts {
				switch o {
				case "net_cls":
				case "net_prio":
				default:
					continue
				}
				if cgroupTypes == "" {
					cgroupTypes = o
				} else {
					cgroupTypes = fmt.Sprintf("%s,%s", cgroupTypes, o)
				}
			}
			if cgroupTypes != "" {
				cgroupNetMounts[cgroupTypes] = mount.MountPoint
			}
		}
	})
	return cgroupNetMounts
}
