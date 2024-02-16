// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/mountinfo"
)

var (
	// Path to where bpffs is mounted
	bpffsRoot = defaults.BPFFSRoot

	// Set to true on first get request to detect misorder
	lockedDown      = false
	once            sync.Once
	readMountInfo   sync.Once
	mountInfoPrefix string
)

func lockDown() {
	lockedDown = true
}

func setBPFFSRoot(path string) {
	if lockedDown {
		panic("setBPFFSRoot() call after bpffsRoot was read")
	}
	bpffsRoot = path
}

func BPFFSRoot() string {
	once.Do(lockDown)
	return bpffsRoot
}

// TCGlobalsPath returns the absolute path to <bpffs>/tc/globals, used for
// legacy map pin paths.
func TCGlobalsPath() string {
	once.Do(lockDown)
	return filepath.Join(bpffsRoot, defaults.TCGlobalsPath)
}

// CiliumPath returns the bpffs path to be used for Cilium object pins.
func CiliumPath() string {
	once.Do(lockDown)
	return filepath.Join(bpffsRoot, "cilium")
}

// MkdirBPF wraps [os.MkdirAll] with the right permission bits for bpffs.
// Use this for ensuring the existence of directories on bpffs.
func MkdirBPF(path string) error {
	return os.MkdirAll(path, 0755)
}

func tcPathFromMountInfo(name string) string {
	readMountInfo.Do(func() {
		mountInfos, err := mountinfo.GetMountInfo()
		if err != nil {
			log.WithError(err).Fatal("Could not get mount info for map root lookup")
		}

		for _, mountInfo := range mountInfos {
			if mountInfo.FilesystemType == "bpf" {
				mountInfoPrefix = filepath.Join(mountInfo.MountPoint, defaults.TCGlobalsPath)
				return
			}
		}

		log.Fatal("Could not find BPF map root")
	})

	return filepath.Join(mountInfoPrefix, name)
}

// MapPath returns a path for a BPF map with a given name.
func MapPath(name string) string {
	if components.IsCiliumAgent() {
		once.Do(lockDown)
		return filepath.Join(TCGlobalsPath(), name)
	}
	return tcPathFromMountInfo(name)
}

// LocalMapName returns the name for a BPF map that is local to the specified ID.
func LocalMapName(name string, id uint16) string {
	return fmt.Sprintf("%s%05d", name, id)
}

// LocalMapPath returns the path for a BPF map that is local to the specified ID.
func LocalMapPath(name string, id uint16) string {
	return MapPath(LocalMapName(name, id))
}

var (
	mountOnce sync.Once
)

// mountFS mounts the BPFFS filesystem into the desired mapRoot directory.
func mountFS(printWarning bool) error {
	if printWarning {
		log.Warning("================================= WARNING ==========================================")
		log.Warning("BPF filesystem is not mounted. This will lead to network disruption when Cilium pods")
		log.Warning("are restarted. Ensure that the BPF filesystem is mounted in the host.")
		log.Warning("https://docs.cilium.io/en/stable/operations/system_requirements/#mounted-ebpf-filesystem")
		log.Warning("====================================================================================")
	}

	log.Infof("Mounting BPF filesystem at %s", bpffsRoot)

	mapRootStat, err := os.Stat(bpffsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			if err := MkdirBPF(bpffsRoot); err != nil {
				return fmt.Errorf("unable to create bpf mount directory: %s", err)
			}
		} else {
			return fmt.Errorf("failed to stat the mount path %s: %s", bpffsRoot, err)

		}
	} else if !mapRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", bpffsRoot)
	}

	if err := unix.Mount(bpffsRoot, bpffsRoot, "bpf", 0, ""); err != nil {
		return fmt.Errorf("failed to mount %s: %s", bpffsRoot, err)
	}
	return nil
}

// hasMultipleMounts checks whether the current mapRoot has only one mount.
func hasMultipleMounts() (bool, error) {
	num := 0

	mountInfos, err := mountinfo.GetMountInfo()
	if err != nil {
		return false, err
	}

	for _, mountInfo := range mountInfos {
		if mountInfo.Root == "/" && mountInfo.MountPoint == bpffsRoot {
			num++
		}
	}

	return num > 1, nil
}

// checkOrMountCustomLocation tries to check or mount the BPF filesystem in the
// given path.
func checkOrMountCustomLocation(bpfRoot string) error {
	setBPFFSRoot(bpfRoot)

	// Check whether the custom location has a BPFFS mount.
	mounted, bpffsInstance, err := mountinfo.IsMountFS(mountinfo.FilesystemTypeBPFFS, bpfRoot)
	if err != nil {
		return err
	}

	// If the custom location has no mount, let's mount BPFFS there.
	if !mounted {
		setBPFFSRoot(bpfRoot)
		if err := mountFS(true); err != nil {
			return err
		}

		return nil
	}

	// If the custom location already has a mount with some other filesystem than
	// BPFFS, return the error.
	if !bpffsInstance {
		return fmt.Errorf("mount in the custom directory %s has a different filesystem than BPFFS", bpfRoot)
	}

	log.Infof("Detected mounted BPF filesystem at %s", bpffsRoot)

	return nil
}

// checkOrMountDefaultLocations tries to check or mount the BPF filesystem in
// standard locations, which are:
// - /sys/fs/bpf
// - /run/cilium/bpffs
// There is a procedure of determining which directory is going to be used:
//  1. Checking whether BPFFS filesystem is mounted in /sys/fs/bpf.
//  2. If there is no mount, then mount BPFFS in /sys/fs/bpf and finish there.
//  3. If there is a BPFFS mount, finish there.
//  4. If there is a mount, but with the other filesystem, then it means that most
//     probably Cilium is running inside container which has mounted /sys/fs/bpf
//     from host, but host doesn't have proper BPFFS mount, so that mount is just
//     the empty directory. In that case, mount BPFFS under /run/cilium/bpffs.
func checkOrMountDefaultLocations() error {
	// Check whether /sys/fs/bpf has a BPFFS mount.
	mounted, bpffsInstance, err := mountinfo.IsMountFS(mountinfo.FilesystemTypeBPFFS, bpffsRoot)
	if err != nil {
		return err
	}

	// If /sys/fs/bpf is not mounted at all, we should mount
	// BPFFS there.
	if !mounted {
		if err := mountFS(false); err != nil {
			return err
		}

		return nil
	}

	if !bpffsInstance {
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
			"for more information, see: https://cilium.link/err-bpf-mount",
			defaults.BPFFSRootFallback,
		)
		setBPFFSRoot(defaults.BPFFSRootFallback)

		cMounted, cBpffsInstance, err := mountinfo.IsMountFS(mountinfo.FilesystemTypeBPFFS, bpffsRoot)
		if err != nil {
			return err
		}
		if !cMounted {
			if err := mountFS(false); err != nil {
				return err
			}
		} else if !cBpffsInstance {
			log.Fatalf("%s is mounted but has a different filesystem than BPFFS", defaults.BPFFSRootFallback)
		}
	}

	log.Infof("Detected mounted BPF filesystem at %s", bpffsRoot)

	return nil
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
		return fmt.Errorf("multiple mount points detected at %s", bpffsRoot)
	}

	return nil
}

// CheckOrMountFS checks or mounts the BPF filesystem and then
// opens/creates/deletes all maps which have previously been scheduled to be
// opened/created/deleted.
//
// If printWarning is set, will print a warning if bpffs has not previously been
// mounted.
func CheckOrMountFS(bpfRoot string) {
	mountOnce.Do(func() {
		if err := checkOrMountFS(bpfRoot); err != nil {
			log.WithError(err).Fatal("Unable to mount BPF filesystem")
		}
	})
}
