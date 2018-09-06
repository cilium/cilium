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

package sockops

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mountinfo"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
)

var (
	// Path to where cgroup is mounted
	cgroupRoot = defaults.DefaultCgroupRoot

	// Set to true on first get request to detect misorder
	cgrpLockedDown = false

	// Only mount a single instance
	cgrpMountOnce sync.Once

	// Program load path
	bpfSockopsProg = "sockops"

	// Set to true after sockopsRoot beomes in-use
	sockopsLockedDown = false
	skmsgLockedDown   = false

	// Mutex to sync access to sockops Root
	sockopsMutex lock.Mutex

	contextTimeout = 5 * time.Minute

	once sync.Once
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "sockops")

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
			return fmt.Errorf("failed to stat the mount path %s: %s", cgroupRoot, err)
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

func bpftoolMapAttach(bpfObject string) error {
	prog := "bpftool"
	//bpffs := bpf.GetMapRoot() + "/" + bpfObject

	args := []string{}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Map Attach BPF Object:")
	_, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to map attach %s: %s", bpfObject, err)
	}
	return nil
}

// #bpftool cgroup attach $cgrp sock_ops /sys/fs/bpf/$bpfObject
func bpftoolAttach(bpfObject string) error {
	prog := "bpftool"
	bpffs := bpf.GetMapRoot() + "/" + bpfObject
	cgrp := cgroupRoot

	args := []string{"cgroup", "attach", cgrp, "sock_ops", "pinned", bpffs}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Attach BPF Object:")
	_, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to attach %s: %s", bpfObject, err)
	}
	return nil
}

// #bpftool cgroup detach $cgrp sock_ops /sys/fs/bpf/$bpfObject
func bpftoolDetach(bpfObject string) error {
	prog := "bpftool"
	bpffs := bpf.GetMapRoot() + "/" + bpfObject
	cgrp := cgroupRoot

	args := []string{"cgroup", "detach", cgrp, "sock_ops", "pinned", bpffs}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Detach BPF Object:")
	_, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to detach %s: %s", bpfObject, err)
	}
	return nil

}

// #bpftool prog load $bpfObject /sys/fs/bpf/sockops
func bpftoolLoad(bpfObject string, bpfFsFile string) error {
	prog := "bpftool"
	bpffs := bpf.GetMapRoot() + "/" + bpfFsFile

	args := []string{"prog", "load", bpfObject, bpffs}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Load BPF Object:")
	_, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load %s: %s", bpfObject, err)
	}
	return nil
}

// #rm $bpfObject
func bpftoolUnload(bpfObject string) {
	bpffs := bpf.GetMapRoot() + "/" + bpfObject

	os.Remove(bpffs)
}

// #bpftool prog show pinned /sys/fs/bpf/bpf_sockops
// #bpftool map show id 21
func bpftoolGetMapId(progName string, mapName string) (error, int) {
	bpffs := bpf.GetMapRoot() + "/" + progName
	prog := "bpftool"

	args := []string{"prog", "show", "pinned", bpffs}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Load BPF Object:")
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load %s: %s", progName, err), 0
	}

	// Scrap the map_id out of the bpftool output after libbpf is dual licensed
	// we will use programatic API.
	s := strings.Fields(string(output))
	for i := range s {
		if s[i] == "map_ids" {
			fmt.Printf(s[i])
			fmt.Printf(s[i+1])
			id := strings.Split(s[i+1], ",")
			for j := range id {
				fmt.Printf(id[j])
				args := []string{"map", "show", "id", id[j]}
				output, err := exec.Command(prog, args...).CombinedOutput()
				if err != nil {
					return err, 0
				}

				if strings.Contains(string(output), mapName) {
					fmt.Printf(string(j))
					map_id, _ := strconv.Atoi(id[j])
					fmt.Printf("\n from string %s map_id: %d\n", id[j], map_id)
					return nil, map_id
				}
			}
			break
		}
	}
	return nil, 0
}

// #bpftool map pin id map_id /sys/fs/bpf/tc/globals
func bpftoolPinMapId(mapName string, map_id int) error {
	bpffs := bpf.GetMapRoot()
	globals := bpffs + "/" + "tc/globals/"
	mapFile := globals + mapName
	prog := "bpftool"

	fmt.Printf("\nmap2string %s map_id %d\n", strconv.Itoa(map_id), map_id)
	args := []string{"map", "pin", "id", strconv.Itoa(map_id), mapFile}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Map pin:")
	_, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to pin map %d(%s): %s", map_id, mapName, err)
	}

	return nil
}

// #clang ... | llc ...
func bpfCompileProg(src string, dst string) error {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()
	//wd, err := os.Getwd()
	//if err != nil {
	//		return fmt.Errorf("failed Getwd when loading sockops: %s", err)
	//	}

	srcpath := filepath.Join("sockops", src)
	outpath := filepath.Join(dst)

	err := loader.Compile(ctx, srcpath, outpath)
	if err != nil {
		return fmt.Errorf("failed compile %s: %s", srcpath, err)
	}
	return nil
}

// First user of sockops root is sockops load programs so we ensure the sockops
// root path no longer changes.
func bpfLoadAttachProg(object string, load string, mapName string) (error, int, int) {
	sockopsObj := option.Config.StateDir + "/" + object
	map_id := 0

	err := bpftoolLoad(sockopsObj, load)
	if err != nil {
		return err, 0, 0
	}
	err = bpftoolAttach(load)
	if err != nil {
		return err, 0, 0
	}

	if mapName != "" {
		err, map_id = bpftoolGetMapId(load, mapName)
		if err != nil {
			return err, 0, map_id
		}

		err = bpftoolPinMapId(mapName, map_id)
		if err != nil {
			return err, 0, map_id
		}
	}
	sockopsLockedDown = true
	return nil, 0, map_id
}

func bpfLoadMapProg(object string, load string) error {
	sockops := object
	sockopsObj := option.Config.StateDir + "/" + sockops
	sockopsLoad := load

	err := bpftoolLoad(sockopsObj, sockopsLoad)
	if err != nil {
		return err
	}
	err = bpftoolMapAttach(sockopsLoad)
	if err != nil {
		return err
	}
	skmsgLockedDown = true
	return nil
}

func SkmsgEnable() error {
	err := bpfCompileProg("bpf_ipc.c", "bpf_ipc.o")
	if err != nil {
		log.Error(err)
		return err
	}

	err = bpfLoadMapProg("bpf_ipc.o", "bpf_ipc")
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func SkmsgDisable() {
	bpftoolUnload("bpf_ipc")
}

func SockmapEnable() error {
	err := bpfCompileProg("bpf_sockops.c", "bpf_sockops.o")
	if err != nil {
		log.Error(err)
		return err
	}
	err, prog_id, map_id := bpfLoadAttachProg("bpf_sockops.o", "bpf_sockops", "sock_ops_map")
	if err != nil {
		log.Error(err)
		return err
	}
	fmt.Printf("bpf_sockops prog_id %d map_id %d\n", prog_id, map_id)
	return nil
}

func SockmapDisable() {
	bpftoolDetach("bpf_sockops")
	bpftoolUnload("bpf_sockops")
	sockopsLockedDown = false
}
