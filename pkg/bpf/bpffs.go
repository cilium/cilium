// Copyright 2016-2017 Authors of Cilium
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
	"path"
	"sync"

	log "github.com/Sirupsen/logrus"
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

	mountMutex.Lock()
	for _, m := range delayedOpens {
		m.OpenOrCreate()
	}

	mounted = true
	delayedOpens = []*Map{}
	mountMutex.Unlock()
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
	return path.Join(mapRoot, mapPrefix)
}

func MapPath(name string) string {
	once.Do(lockDown)
	return path.Join(mapRoot, mapPrefix, name)
}

var (
	mountOnce    sync.Once
	mountMutex   sync.Mutex
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
			return fmt.Errorf("Command execution failed: %s\n%s", err, out)
		}
	}

	mountMutex.Lock()
	for _, m := range delayedOpens {
		m.OpenOrCreate()
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
			log.WithError(err).Fatalf("Unable to mount BPF filesystem")
		}
	})
}
