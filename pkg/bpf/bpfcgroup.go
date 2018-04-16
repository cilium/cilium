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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"golang.org/x/sys/unix"
)

var (
	// ExecTimeout is the execution timeout to use in sockops/txmsg scripts
	ExecTimeout = 300 * time.Second
	sockopsLib  = "./"

	// TBD pull this from actual config
	bpfRundir = "/var/run/cilium/state"
	bpfDir    = "/var/lib/cilium/bpf"
	bpftool   = "bpftool"
	// Path to where cgroup2 is mounted (default: /mnt/cilium-cgroup2)
	cgroup2 = "/mnt/cilium-cgroup2"
	// Path to where sockops program is (default: $CILIUM/bpf_sockops.c)
	sockops = "sockops"
	// Path to where sockops program is (default: $CILIUM/bpf_ipc.c)
	txmsg = "ipc.sh"
)

func SetCgroupPath(path string) {
	cgroup2 = path
}

func GetCgroupPath() string {
	return cgroup2
}

func SetSockopsPath(path string) {
	sockops = path
}

func GetSockopsPath() string {
	return sockops
}

func SetTxmsgPath(path string) {
	txmsg = path
}

func GetTxmsgPath() string {
	return txmsg
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

func SockopsRunProgram(op string, cmd string) error {
	pin := filepath.Join(GetMapRoot(), GetSockopsPath())
	prog := bpftool
	args := []string{"cgroup", cmd, cgroup2, "sock_ops", "pinned", pin}

	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()
	out, err := exec.Command(prog, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		cmd := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
		log.WithField("cmd", cmd).Error("Command execution failed: Timeout")
		return fmt.Errorf("Command execution failed: Timeout for %s %s", prog, args)
	}
	if err != nil {
		cmdt := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
		log.WithField("cmd", cmdt).Error("Command execution failed")

		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			log.Warn(scanner.Text())
		}
		return err
	}

	return nil
}

func AttachSockopsProgram() error {
	return SockopsRunProgram("sockops", "attach")
}

func DetachSockopsProgram() error {
	return SockopsRunProgram("sockops", "detach")
}

func StatusSockopsProgram() (bool, error) {
	prog := bpftool
	args := []string{"cgroup", "list", cgroup2}

	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()
	out, err := exec.Command(prog, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		cmd := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
		log.WithField("cmd", cmd).Error("Command execution failed: Timeout")
		return false, fmt.Errorf("Command execution failed: Timeout for %s %s", prog, args)
	}

	if err != nil {
		cmdt := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
		log.WithField("cmd", cmdt).Error("Command execution failed")

		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			log.Warn(scanner.Text())
		}
		return false, err
	}
	match, _ := regexp.MatchString("bpf_sockmap", string(out))
	return match, nil
}
