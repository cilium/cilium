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
	"io/ioutil"
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

	// Default prefix for map objects
	mapPrefix = defaults.DefaultMapPrefix

	// Set to true after sockopsRoot beomes in-use
	sockopsLockedDown = false
	skmsgLockedDown   = false

	// Mutex to sync access to sockops Root
	sockopsMutex lock.Mutex

	contextTimeout = 5 * time.Minute

	once sync.Once

	// BPF Program load path
	cSockops = "bpf_sockops.c"
	oSockops = "bpf_sockops.o"
	eSockops = "bpf_sockops"

	cIPC = "bpf_redir.c"
	oIPC = "bpf_redir.o"
	eIPC = "bpf_redir"

	sockMap = "sock_ops_map"
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
				return fmt.Errorf("Unable to create cgroup mount directory: %s", err)
			}
		} else {
			return fmt.Errorf("Failed to stat the mount path %s: %s", cgroupRoot, err)
		}
	} else if !cgroupRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", cgroupRoot)
	}

	mnt_args := []string{"-t", "cgroup2", "none", cgroupRoot}
	_, err = exec.Command(prog, mnt_args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to mount %s: %s", cgroupRoot, err)
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
		return fmt.Errorf("Mount in the custom directory %s has a different filesystem than cgroup2", cgroupRoot)
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

// BPF programs and sockmaps working on cgroups
func bpftoolMapAttach(prog_id string, map_id string) error {
	prog := "bpftool"

	args := []string{"prog", "attach", "id", prog_id, "msg_verdict", "id", map_id}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Map Attach BPF Object:")
	_, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to attach prog(%s) to map(%s): %s", prog_id, map_id, err)
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
		return fmt.Errorf("Failed to attach %s: %s", bpfObject, err)
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
		return fmt.Errorf("Failed to detach %s: %s", bpfObject, err)
	}
	return nil

}

// #bpftool prog load $bpfObject /sys/fs/bpf/sockops
func bpftoolLoad(bpfObject string, bpfFsFile string) error {
	prog := "bpftool"
	var map_arg_list []string
	bpffs := bpf.GetMapRoot() + "/" + bpfFsFile
	sockops_maps := []string{
		"cilium_lxc",
		"cilium_metric",
		"cilium_events",
		"sock_ops_map",
		"cilium_ep_to_policy",
		"cilium_proxy4", "cilium_proxy6",
		"cilium_lb6_reverse_nat", "cilium_lb4_reverse_nat",
		"cilium_lb6_services", "cilium_lb4_services",
		"cilium_lb6_rr_seq", "cilium_lb4_seq",
		"cilium_lb6_rr_seq", "cilium_lb4_seq",
	}

	maps, err := ioutil.ReadDir(bpf.GetMapRoot() + "/tc/globals/")
	if err != nil {
		return err
	}

	for _, f := range maps {
		// Ignore all backing files
		if strings.HasPrefix(f.Name(), "..") {
			continue
		}

		use := func() bool {
			for _, n := range sockops_maps {
				if f.Name() == n {
					return true
				}
			}
			return false
		}()

		if !use {
			continue
		}

		fmt.Printf("use %s\n", f.Name())
		map_string := []string{"map", "name", f.Name(), "pinned", bpf.GetMapRoot() + "/tc/globals/" + f.Name()}
		map_arg_list = append(map_arg_list, map_string...)
	}

	args := []string{"-m", "prog", "load", bpfObject, bpffs}
	args = append(args, map_arg_list...)
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Load BPF Object:")
	fmt.Printf("\nLoad BPF: %s %s\n", prog, args)
	out, err := exec.Command(prog, args...).CombinedOutput()
	fmt.Printf("LoadBPF: err %s : %s\n", err, out)
	if err != nil {
		return fmt.Errorf("Failed to load %s: %s", bpfObject, err)
	}
	return nil
}

// #rm $bpfObject
func bpftoolUnload(bpfObject string) {
	bpffs := bpf.GetMapRoot() + "/" + bpfObject

	os.Remove(bpffs)
}

// #bpftool prog show pinned /sys/fs/bpf/
func bpftoolGetProgId(progName string) (error, string) {
	bpffs := bpf.GetMapRoot() + "/" + progName
	prog := "bpftool"

	args := []string{"prog", "show", "pinned", bpffs}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("GetProgId:")
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to load %s: %s", progName, err), ""
	}

	// Scrap the prog_id out of the bpftool output after libbpf is dual licensed
	// we will use programatic API.
	s := strings.Fields(string(output))
	if s[0] == "" {
		return fmt.Errorf("Failed to find prog %s: %s", progName, err), ""
	}
	fmt.Printf(s[0])
	prog_id := strings.Split(s[0], ":")
	return nil, prog_id[0]
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
	}).Debug("GetMapId:")
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to load %s: %s", progName, err), 0
	}

	// Find the map_id out of the bpftool output
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
	globals := bpffs + "/" + mapPrefix + "/"
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
		return fmt.Errorf("Failed to pin map %d(%s): %s", map_id, mapName, err)
	}

	return nil
}

// #clang ... | llc ...
func bpfCompileProg(src string, dst string) error {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	srcpath := filepath.Join("sockops", src)
	outpath := filepath.Join(dst)

	err := loader.Compile(ctx, srcpath, outpath)
	if err != nil {
		return fmt.Errorf("failed compile %s: %s", srcpath, err)
	}
	return nil
}

func bpfLoadMapProg(object string, load string) error {
	sockops := object
	sockopsObj := option.Config.StateDir + "/" + sockops
	sockopsLoad := load

	err := bpftoolLoad(sockopsObj, sockopsLoad)
	if err != nil {
		return err
	}

	err, prog_id := bpftoolGetProgId(load)
	if err != nil {
		return err
	}

	err, _map_id := bpftoolGetMapId("bpf_sockops", sockMap)
	map_id := strconv.Itoa(_map_id)
	if err != nil {
		return err
	}

	err = bpftoolMapAttach(prog_id, map_id)
	if err != nil {
		return err
	}
	skmsgLockedDown = true
	return nil
}

func SkmsgEnable() error {
	err := bpfCompileProg(cIPC, oIPC)
	if err != nil {
		log.Error(err)
		return err
	}

	err = bpfLoadMapProg(oIPC, eIPC)
	if err != nil {
		log.Error(err)
		return err
	}
	log.Infof("Sockmsg Enabled, bpf_redir loaded")
	return nil
}

func SkmsgDisable() {
	bpftoolUnload("bpf_redir")
	log.Infof("Sockmsg Disabled.")
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

func SockmapEnable() error {
	err := bpfCompileProg(cSockops, oSockops)
	if err != nil {
		log.Error(err)
		return err
	}
	err, prog_id, map_id := bpfLoadAttachProg(oSockops, eSockops, sockMap)
	if err != nil {
		log.Error(err)
		return err
	}
	log.Infof("Sockmap Enabled: bpf_sockops prog_id %d and map_id %d loaded", prog_id, map_id)
	return nil
}

func SockmapDisable() {
	mapName := mapPrefix + "/" + sockMap
	bpftoolDetach(eSockops)
	bpftoolUnload(eSockops)
	bpftoolUnload(mapName)
	sockopsLockedDown = false
	log.Infof("Sockmap disabled.")
}
