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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/pipeexec"

	"golang.org/x/sys/unix"
)

var (
	// Path to where bpffs is mounted (default: /sys/fs/bpf)
	mapRoot = "/sys/fs/bpf"

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

var (
	mountOnce    sync.Once
	mountMutex   lock.Mutex
	delayedOpens = []*Map{}
	mounted      bool
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

func mountFS() error {
	// Mount BPF Map directory if not already done
	args := []string{"-q", mapRoot}
	_, err := exec.Command("mountpoint", args...).CombinedOutput()
	if err != nil {
		args = []string{"bpffs", mapRoot, "-t", "bpf"}
		out, err := exec.Command("mount", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("command execution failed: %s\n%s", err, out)
		}
	} else { // Already mounted. We need to fail if mounted multiple times.

		// Execute the following command to find multiple bpffs mount points
		// % mount | grep "<mapRoot> " | wc -l | cut -f1 -d' '
		newmapRoot := mapRoot + " " // Append space to ignore /sys/fs/bpf/xdp and /sys/fs/bpf/ip mountpoints.
		cmds := []*exec.Cmd{
			exec.Command("mount"),
			exec.Command("grep", newmapRoot),
			exec.Command("wc", "-l"),
			exec.Command("cut", "-f1", "-d "),
		}

		output, stderr, err := pipeexec.CommandPipe(cmds)
		if len(stderr) > 0 || err != nil {
			return fmt.Errorf("command execution failed: %s", stderr)
		}

		// Strip the newline character at the end.
		parts := strings.Split(string(output), "\n")

		// Convert the string to integer
		num, err := strconv.ParseInt(parts[0], 10, 32)
		if err != nil {
			return fmt.Errorf("command execution failed: %s", err)
		}

		if num > 1 {
			return fmt.Errorf("multiple mount points detected at %s", mapRoot)
		}

	}

	var fsdata unix.Statfs_t
	if err := unix.Statfs(mapRoot, &fsdata); err != nil {
		return fmt.Errorf("BPF filesystem path %s is not mounted", mapRoot)
	}

	// This is the value of the BPF Filesystem defined in
	// uapi/linux/magic.h The magic value can potentially be misleading if
	// the BPF filesystem is mounted in the host and then volume mapped
	// into a container.
	magic := uint32(0xCAFE4A11)
	if uint32(fsdata.Type) != magic {
		log.WithField(logfields.Path, mapRoot).Warningf("BPF root is not a BPF filesystem (%#x != %#x)",
			uint32(fsdata.Type), magic)
	}

	mountMutex.Lock()
	for _, m := range delayedOpens {
		_, err = m.OpenOrCreate()
		if err != nil {
			log.WithError(err).WithField(logfields.BPFMapName, m.name).Error("error opening map after bpffs was mounted")
		}
	}

	mounted = true
	delayedOpens = []*Map{}
	mountMutex.Unlock()

	return nil
}

// MountFS mounts the BPF filesystem and then opens/creates all maps which have
// previously been scheduled to be opened/created
func MountFS() {
	mountOnce.Do(func() {
		if err := mountFS(); err != nil {
			log.WithError(err).Fatal("Unable to mount BPF filesystem")
		}

		log.Infof("Mounted BPF filesystem %s", mapRoot)
	})
}

// UnMountFS unmounts the BPF filesystem.
func UnMountFS() error {
	mountMutex.Lock()
	defer mountMutex.Unlock()

	if err := syscall.Unmount(GetMapRoot(), syscall.MNT_DETACH); err != nil {
		return err
	}

	mounted = false

	return nil
}
