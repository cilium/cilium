// Copyright 2016-2018 Authors of Cilium
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
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/cilium/common/files"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"golang.org/x/sys/unix"
)

const (
	// defaultMapRoot is the default path where BPFFS should be mounted
	defaultMapRoot = "/sys/fs/bpf"
	// defaultMapRootFallback is the path which is used when /sys/fs/bpf has
	// a mount, but with the other filesystem than BPFFS.
	defaultMapRootFallback = "/run/cilium/bpffs"
)

var (
	// Path to where bpffs is mounted
	mapRoot = defaultMapRoot

	// Prefix for all maps (default: tc/globals)
	mapPrefix = "tc/globals"

	// Set to true on first get request to detect misorder
	lockedDown = false
	once       sync.Once
)

func lockDown() {
	lockedDown = true
}

func SetMapRoot(path string) {
	if lockedDown {
		panic("SetMapRoot() call after MapRoot was read")
	}
	mapRoot = path
}

func GetMapRoot() string {
	once.Do(lockDown)
	return mapRoot
}

func SetMapPrefix(path string) {
	if lockedDown {
		panic("SetMapPrefix() call after MapPrefix was read")
	}
	mapPrefix = path
}

func GetMapPrefix() string {
	once.Do(lockDown)
	return mapPrefix
}

func MapPrefixPath() string {
	once.Do(lockDown)
	return filepath.Join(mapRoot, mapPrefix)
}

func MapPath(name string) string {
	once.Do(lockDown)
	return filepath.Join(mapRoot, mapPrefix, name)
}

// TcEnvironment returns a list of environment variables which are needed to
// make tc aware of the actual BPFFS mount path.
func TcEnvironment() []string {
	return append(
		os.Environ(),
		fmt.Sprintf("BPF_ENV_MNT=%s", GetMapRoot()),
	)
}

var (
	mountOnce  sync.Once
	mountMutex lock.Mutex
	// List of BPF maps which are scheduled to be opened/created after the
	// BPF filesystem has been mounted.
	delayedOpens = []*Map{}
	// List of BPF maps which are scheduled to be removed after the BPF
	// filesystem has been mounted.
	delayedRemoves = []string{}
	mounted        bool
)

// OpenAfterMount schedules a map to be opened/created after the BPF filesystem
// has been mounted. If the filesystem is already mounted, the map is
// opened/created immediately.
func OpenAfterMount(m *Map) error {
	mountMutex.Lock()
	defer mountMutex.Unlock()

	if mounted {
		_, err := m.OpenOrCreate()
		return err
	}

	log.WithField(logfields.BPFMapName, m.name).Debug("bpffs is not mounted yet; adding to list of maps to open once it is mounted")
	delayedOpens = append(delayedOpens, m)
	return nil
}

// removeMap removes a map from the BPF filesystem.
func removeMap(name string) {
	os.Remove(MapPath(name))
}

// RemoveAfterMount schedules a map to be deleted after the BPF filesystem has
// been mounted. If the filesystem is already mounted, the map is deleted
// immediately.
func RemoveAfterMount(name string) {
	mountMutex.Lock()
	defer mountMutex.Unlock()

	if mounted {
		removeMap(name)
		return
	}

	log.WithField(logfields.BPFMapName, name).Debug("bpffs is not mounted yet; adding to list of maps to remove once it is mounted")
	delayedRemoves = append(delayedRemoves, name)
}

// mountFS mounts the BPFFS filesystem into the desired mapRoot directory.
func mountFS() error {
	mapRootStat, err := os.Stat(mapRoot)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(mapRoot, 0755)
		} else {
			return fmt.Errorf("failed to stat the mount path %s: %s", mapRoot, err)
		}
	}

	if !mapRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", mapRoot)
	}

	if err := syscall.Mount(mapRoot, mapRoot, "bpf", 0, ""); err != nil {
		return fmt.Errorf("failed to mount %s: %s", mapRoot, err)
	}
	return nil
}

// hasMultipleMounts checks whether the current mapRoot has only one mount.
func hasMultipleMounts() (bool, error) {
	scanner, err := files.NewFileScanner("/proc/mounts")
	if err != nil {
		return false, err
	}
	defer scanner.Close()

	newmapRoot := mapRoot + " " // Append space to ignore /sys/fs/bpf/xdp and /sys/fs/bpf/ip mountpoints.

	num := 0
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), newmapRoot) {
			num++
		}
	}

	return num > 1, nil
}

// isBPFFS returns two boolean values:checks whether the current mapRoot:
// - whether the current mapRoot has any mount
// - whether that mount's filesystem is BPFFS
func isBPFFS() (bool, bool, error) {
	// Check whether mapRoot has any mount (by checking /proc/mounts)
	scanner, err := files.NewFileScanner("/proc/mounts")
	if err != nil {
		return false, false, err
	}

	hasMount := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), mapRoot) {
			hasMount = true
			break
		}
	}
	scanner.Close()

	if !hasMount {
		return false, false, nil
	}

	// Check whether the mount filesystem is BPFFS
	var fsdata unix.Statfs_t
	if err := unix.Statfs(mapRoot, &fsdata); err != nil {
		log.WithError(err).Errorf("unable to get information about %s mount", mapRoot)
		return true, false, err
	}

	// This is the value of the BPF Filesystem defined in
	// uapi/linux/magic.h The magic value can potentially be misleading if
	// the BPF filesystem is mounted in the host and then volume mapped
	// into a container.
	magic := uint32(0xCAFE4A11)

	if uint32(fsdata.Type) == magic {
		return true, true, nil
	}
	return true, false, nil
}

// checkOrMountCustomLocation tries to check or mount the BPF filesystem in the
// given path.
func checkOrMountCustomLocation(bpfRoot string) error {
	SetMapRoot(bpfRoot)

	// Check whether the custom location has a BPFFS mount.
	mounted, bpffsInstance, err := isBPFFS()
	if err != nil {
		return err
	}

	// If the custom location has no mount, let's mount BPFFS there.
	if !mounted {
		SetMapRoot(bpfRoot)
		if err := mountFS(); err != nil {
			return err
		}
	}

	// If the custom location already has a mount with some other filesystem than
	// BPFFS, return the error.
	if !bpffsInstance {
		return fmt.Errorf("mount in the custom directory %s has a different filesystem than BPFFS", bpfRoot)
	}

	return nil
}

// checkOrMountDefaultLocations tries to check or mount the BPF filesystem in
// standard locations, which are:
// - /sys/fs/bpf
// - /run/cilium/bpffs
// There is a procedure of determining which directory is going to be used:
// 1. Checking whether BPFFS filesystem is mounted in /sys/fs/bpf.
// 2. If there is no mount, then mount BPFFS in /sys/fs/bpf and finish there.
// 3. If there is a BPFFS mount, finish there.
// 4. If there is a mount, but with the other filesystem, then it means that most
//    probably Cilium is running inside container which has mounted /sys/fs/bpf
//    from host, but host doesn't have proper BPFFS mount, so that mount is just
//    the empty directory. In that case, mount BPFFS under /run/cilium/bpffs.
func checkOrMountDefaultLocations() error {
	var err error

	// Check whether /sys/fs/bpf has a BPFFS mount.
	mounted, bpffsInstance, err := isBPFFS()
	if err != nil {
		return err
	}

	// If /sys/fs/bpf is not mounted at all, we should mount
	// BPFFS there.
	if !mounted {
		err = mountFS()
	} else if !bpffsInstance {
		// If /sys/fs/bpf has a mount but with some other filesystem
		// than BPFFS, it means that Cilium is running inside container
		// and /sys/fs/bpf is not mounted on host. We should mount BPFFS
		// in /run/cilium/bpffs automatically. This will allow operation
		// of Cilium but will result in unmounting of the filesystem
		// when the pod is restarted. This in turn will cause resources
		// such as the connection tracking table of the BPF programs to
		// be released which will cause all connections into local
		// containers to be dropped. User is going to be warned.
		log.Warnf("BPF filesystem is going to be mounted automatically "+
			"in %s. However, it probably means that Cilium is running "+
			"inside container and BPFFS is not mounted on the host. "+
			"We recommend to do that: https://cilium.link/err-bpf-mount",
			defaultMapRootFallback,
		)
		SetMapRoot(defaultMapRootFallback)

		cMounted, cBpffsInstance, err := isBPFFS()
		if err != nil {
			return err
		}
		if !cMounted {
			err = mountFS()
		} else if !cBpffsInstance {
			log.Fatalf("%s is mounted but has a different filesystem than BPFFS", defaultMapRootFallback)
		}
	}

	return err
}

func checkOrMountFS(bpfRoot string) error {
	if bpfRoot == "" {
		if err := checkOrMountDefaultLocations(); err != nil {
			return err
		}
	} else {
		if err := checkOrMountCustomLocation(bpfRoot); err != nil {
			return err
		}
	}

	multipleMounts, err := hasMultipleMounts()
	if err != nil {
		return err
	}
	if multipleMounts {
		return fmt.Errorf("multiple mount points detected at %s", mapRoot)
	}

	mountMutex.Lock()
	for _, m := range delayedOpens {
		if _, err := m.OpenOrCreate(); err != nil {
			log.WithError(err).WithField(logfields.BPFMapName, m.name).Error("error opening map after bpffs was mounted")
		}
	}
	for _, m := range delayedRemoves {
		removeMap(m)
	}

	mounted = true
	delayedOpens = []*Map{}
	delayedRemoves = []string{}
	mountMutex.Unlock()

	return nil
}

// CheckOrMountFS checks or mounts the BPF filesystem and then
// opens/creates/deletes all maps which have previously been scheduled to be
// opened/created/deleted.
func CheckOrMountFS(bpfRoot string) {
	mountOnce.Do(func() {
		if err := checkOrMountFS(bpfRoot); err != nil {
			log.WithError(err).Fatal("Unable to mount BPF filesystem")
		}

		log.Infof("Mounted BPF filesystem %s", mapRoot)
	})
}
