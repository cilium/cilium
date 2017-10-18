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
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/syncbytes"

	log "github.com/sirupsen/logrus"
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

	delayedOpens = append(delayedOpens, m)
	return nil
}

//isBpffs check if the path is a valid bpf filesystem
func isBpffs(path string) bool {
	// This is the value of the BPF Filesystem. If is into the container the
	// mountpoint doesn't provide enough information. Defined on uapi/linux/magic.h
	magic := uint32(0xCAFE4A11)
	var fsdata unix.Statfs_t
	if err := unix.Statfs(path, &fsdata); err != nil {
		log.WithField(logfields.Path, path).Error("BPF filesystem path is not mounted")
		return false
	}
	return int32(magic) == int32(fsdata.Type)
}

func mountCmdPipe(cmds []*exec.Cmd) (mountCmdOutput, mountCmdStandardError []byte, mountCmdError error) {

	// We need atleast one command to pipe.
	if len(cmds) < 1 {
		return nil, nil, nil
	}

	// Total output of commands.
	var output syncbytes.Buffer
	var stderr syncbytes.Buffer

	lastCmd := len(cmds) - 1
	for i, cmd := range cmds[:lastCmd] {
		var err error
		// We need to connect every command's stdin to the previous command's stdout
		if cmds[i+1].Stdin, err = cmd.StdoutPipe(); err != nil {
			return nil, nil, err
		}
		// We need to connect each command's stderr to a buffer
		cmd.Stderr = &stderr
	}

	// Connect the output and error for the last command
	cmds[lastCmd].Stdout, cmds[lastCmd].Stderr = &output, &stderr

	// Let's start each command
	for _, cmd := range cmds {
		if err := cmd.Start(); err != nil {
			return output.Bytes(), stderr.Bytes(), err
		}
	}

	// We wait for each command to complete
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			return output.Bytes(), stderr.Bytes(), err
		}
	}

	// Return the output and the standard error
	return output.Bytes(), stderr.Bytes(), nil
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

		output, stderr, _ := mountCmdPipe(cmds)

		if len(stderr) > 0 {
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
	if !isBpffs(mapRoot) {
		// TODO currently on minikube isBpffs check is failing. We need to make the following log
		// fatal again. This will be tracked in #Issue 1475
		//log.WithField(logfields.Path, mapRoot).Fatal("BPF: path is not mounted as a BPF filesystem.")
		log.WithField(logfields.Path, mapRoot).Debug("BPF: path is not mounted as a BPF filesystem.")
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
			log.WithError(err).Fatal("Unable to mount BPF filesystem")
		}
	})
}
