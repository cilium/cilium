// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockops

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const (
	cSockops = "bpf_sockops.c"
	oSockops = "bpf_sockops.o"
	eSockops = "bpf_sockops"

	cIPC = "bpf_redir.c"
	oIPC = "bpf_redir.o"
	eIPC = "bpf_redir"

	sockMap = "cilium_sock_ops"

	// Default prefix for map objects
	mapPrefix = defaults.TCGlobalsPath

	contextTimeout = 5 * time.Minute
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "sockops")

// BPF programs and sockmaps working on cgroups
func bpftoolMapAttach(progID string, mapID string) error {
	prog := "bpftool"

	args := []string{"prog", "attach", "id", progID, "msg_verdict", "id", mapID}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Map Attach BPF Object:")
	out, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to attach prog(%s) to map(%s): %s: %s", progID, mapID, err, out)
	}
	return nil
}

// #bpftool cgroup attach $cgrp sock_ops /sys/fs/bpf/$bpfObject
func bpftoolAttach(bpfObject string) error {
	prog := "bpftool"
	bpffs := filepath.Join(bpf.BPFFSRoot(), bpfObject)
	cgrp := cgroups.GetCgroupRoot()

	args := []string{"cgroup", "attach", cgrp, "sock_ops", "pinned", bpffs}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Attach BPF Object:")
	out, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to attach %s: %s: %s", bpfObject, err, out)
	}
	return nil
}

// #bpftool cgroup detach $cgrp sock_ops /sys/fs/bpf/$bpfObject
func bpftoolDetach(bpfObject string) error {
	prog := "bpftool"
	bpffs := filepath.Join(bpf.BPFFSRoot(), bpfObject)
	cgrp := cgroups.GetCgroupRoot()

	args := []string{"cgroup", "detach", cgrp, "sock_ops", "pinned", bpffs}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Detach BPF Object:")
	out, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to detach %s: %s: %s", bpfObject, err, out)
	}
	return nil

}

// #bpftool prog load $bpfObject /sys/fs/bpf/sockops
func bpftoolLoad(bpfObject string, bpfFsFile string) error {
	sockopsMaps := [...]string{
		"cilium_lxc",
		"cilium_ipcache",
		"cilium_metric",
		"cilium_events",
		"cilium_sock_ops",
		"cilium_ep_to_policy",
		"cilium_proxy4", "cilium_proxy6",
		"cilium_lb6_reverse_nat", "cilium_lb4_reverse_nat",
		"cilium_lb6_services", "cilium_lb4_services",
		"cilium_lb6_rr_seq", "cilium_lb4_seq",
		"cilium_lb6_rr_seq", "cilium_lb4_seq",
	}

	prog := "bpftool"
	var mapArgList []string
	bpffs := filepath.Join(bpf.BPFFSRoot(), bpfFsFile)

	maps, err := os.ReadDir(filepath.Join(bpf.BPFFSRoot(), "/tc/globals/"))
	if err != nil {
		return err
	}

	for _, f := range maps {
		// Ignore all backing files
		if strings.HasPrefix(f.Name(), "..") {
			continue
		}

		use := func() bool {
			for _, n := range sockopsMaps {
				if f.Name() == n {
					return true
				}
			}
			return false
		}()

		if !use {
			continue
		}

		mapString := []string{"map", "name", f.Name(), "pinned", filepath.Join(bpf.BPFFSRoot(), "/tc/globals/", f.Name())}
		mapArgList = append(mapArgList, mapString...)
	}

	args := []string{"-m", "prog", "load", bpfObject, bpffs}
	args = append(args, mapArgList...)
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Load BPF Object:")
	out, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to load %s: %s: %s", bpfObject, err, out)
	}
	return nil
}

// #rm $bpfObject
func bpftoolUnload(bpfObject string) {
	bpffs := filepath.Join(bpf.BPFFSRoot(), bpfObject)

	os.Remove(bpffs)
}

// #bpftool prog show pinned /sys/fs/bpf/
func bpftoolGetProgID(progName string) (string, error) {
	bpffs := filepath.Join(bpf.BPFFSRoot(), progName)
	prog := "bpftool"

	args := []string{"prog", "show", "pinned", bpffs}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("GetProgID:")
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Failed to load %s: %s: %s", progName, err, output)
	}

	// Scrap the prog_id out of the bpftool output after libbpf is dual licensed
	// we will use programatic API.
	s := strings.Fields(string(output))
	if s[0] == "" {
		return "", fmt.Errorf("Failed to find prog %s: %s", progName, err)
	}
	progID := strings.Split(s[0], ":")
	return progID[0], nil
}

// #bpftool prog show pinned /sys/fs/bpf/bpf_sockops
// #bpftool map show id 21
func bpftoolGetMapID(progName string, mapName string) (int, error) {
	bpffs := filepath.Join(bpf.BPFFSRoot(), progName)
	prog := "bpftool"

	args := []string{"prog", "show", "pinned", bpffs}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("GetMapID:")
	output, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("Failed to load %s: %s: %s", progName, err, output)
	}

	// Find the mapID out of the bpftool output
	s := strings.Fields(string(output))
	for i := range s {
		if s[i] == "map_ids" {
			id := strings.Split(s[i+1], ",")
			for j := range id {
				args := []string{"map", "show", "id", id[j]}
				output, err := exec.Command(prog, args...).CombinedOutput()
				if err != nil {
					return 0, err
				}

				if strings.Contains(string(output), mapName) {
					mapID, _ := strconv.Atoi(id[j])
					return mapID, nil
				}
			}
			break
		}
	}
	return 0, nil
}

// #bpftool map pin id map_id /sys/fs/bpf/tc/globals
func bpftoolPinMapID(mapName string, mapID int) error {
	mapFile := filepath.Join(bpf.BPFFSRoot(), mapPrefix, mapName)
	prog := "bpftool"

	args := []string{"map", "pin", "id", strconv.Itoa(mapID), mapFile}
	log.WithFields(logrus.Fields{
		"bpftool": prog,
		"args":    args,
	}).Debug("Map pin:")
	out, err := exec.Command(prog, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to pin map %d(%s): %s: %s", mapID, mapName, err, out)
	}

	return nil
}

// #clang ... | llc ...
func bpfCompileProg(src string, dst string) error {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	srcpath := filepath.Join("sockops", src)
	outpath := filepath.Join(dst)

	err := loader.CompileWithOptions(ctx, srcpath, outpath, option.Config.CompilerFlags)
	if err != nil {
		return fmt.Errorf("failed compile %s: %s", srcpath, err)
	}
	return nil
}

func bpfLoadMapProg(object string, load string) error {
	sockops := object
	sockopsObj := filepath.Join(option.Config.StateDir, sockops)
	sockopsLoad := load

	err := bpftoolLoad(sockopsObj, sockopsLoad)
	if err != nil {
		return err
	}

	progID, err := bpftoolGetProgID(load)
	if err != nil {
		return err
	}

	_mapID, err := bpftoolGetMapID(eSockops, sockMap)
	mapID := strconv.Itoa(_mapID)
	if err != nil {
		return err
	}

	err = bpftoolMapAttach(progID, mapID)
	if err != nil {
		return err
	}
	return nil
}

// SkmsgEnable will compile and attach the SK_MSG programs to the
// sockmap. After this all sockets added to the cilium_sock_ops will
// have sendmsg/sendfile calls running through BPF program.
func SkmsgEnable() error {
	err := bpfCompileProg(cIPC, oIPC)
	if err != nil {
		return err
	}

	err = bpfLoadMapProg(oIPC, eIPC)
	if err != nil {
		return err
	}
	log.Info("Sockmsg Enabled, bpf_redir loaded")
	return nil
}

// SkmsgDisable "unloads" the SK_MSG program. This simply deletes
// the file associated with the program.
func SkmsgDisable() {
	bpftoolUnload(eIPC)
}

// First user of sockops root is sockops load programs so we ensure the sockops
// root path no longer changes.
func bpfLoadAttachProg(object string, load string, mapName string) (int, int, error) {
	sockopsObj := filepath.Join(option.Config.StateDir, object)
	mapID := 0

	err := bpftoolLoad(sockopsObj, load)
	if err != nil {
		return 0, 0, err
	}
	err = bpftoolAttach(load)
	if err != nil {
		return 0, 0, err
	}

	if mapName != "" {
		mapID, err = bpftoolGetMapID(load, mapName)
		if err != nil {
			return 0, mapID, err
		}

		err = bpftoolPinMapID(mapName, mapID)
		if err != nil {
			return 0, mapID, err
		}
	}
	return 0, mapID, nil
}

// SockmapEnable will compile sockops programs and attach the sockops programs
// to the cgroup. After this all TCP connect events will be filtered by a BPF
// sockops program.
func SockmapEnable() error {
	err := bpfCompileProg(cSockops, oSockops)
	if err != nil {
		return err
	}
	progID, mapID, err := bpfLoadAttachProg(oSockops, eSockops, sockMap)
	if err != nil {
		return err
	}
	log.Infof("Sockmap Enabled: bpf_sockops prog_id %d and map_id %d loaded", progID, mapID)
	return nil
}

// SockmapDisable will detach any sockmap programs from cgroups then "unload"
// all the programs and maps associated with it. Here "unload" just means
// deleting the file associated with the map.
func SockmapDisable() {
	mapName := filepath.Join(mapPrefix, sockMap)
	bpftoolDetach(eSockops)
	bpftoolUnload(eSockops)
	bpftoolUnload(mapName)
}
