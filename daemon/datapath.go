// Copyright 2016-2019 Authors of Cilium
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

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/datapath/alignchecker"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
)

func (d *Daemon) compileBase() error {
	var args []string
	var mode string
	var ret error

	type setting struct {
		name      string
		val       string
		ignoreErr bool
	}

	args = make([]string, initArgMax)

	sysSettings := []setting{
		{"net.core.bpf_jit_enable", "1", true},
		{"net.ipv4.conf.all.rp_filter", "0", false},
		{"kernel.unprivileged_bpf_disabled", "1", true},
	}

	// Lock so that endpoints cannot be built while we are compile base programs.
	d.compilationMutex.Lock()
	defer d.compilationMutex.Unlock()

	if err := d.writeNetdevHeader("./"); err != nil {
		log.WithError(err).Warn("Unable to write netdev header")
		return err
	}
	d.datapath.Loader().Init(d.datapath, &d.nodeDiscovery.LocalConfig)

	scopedLog := log.WithField(logfields.XDPDevice, option.Config.DevicePreFilter)
	if option.Config.DevicePreFilter != "undefined" {
		if err := prefilter.ProbePreFilter(option.Config.DevicePreFilter, option.Config.ModePreFilter); err != nil {
			scopedLog.WithError(err).Warn("Turning off prefilter")
			option.Config.DevicePreFilter = "undefined"
		}
	}
	if option.Config.DevicePreFilter != "undefined" {
		if d.preFilter, ret = prefilter.NewPreFilter(); ret != nil {
			scopedLog.WithError(ret).Warn("Unable to init prefilter")
			return ret
		}

		if err := d.writePreFilterHeader("./"); err != nil {
			scopedLog.WithError(err).Warn("Unable to write prefilter header")
			return err
		}

		args[initArgDevicePreFilter] = option.Config.DevicePreFilter
		args[initArgModePreFilter] = option.Config.ModePreFilter
	}

	args[initArgLib] = option.Config.BpfDir
	args[initArgRundir] = option.Config.StateDir
	args[initArgCgroupRoot] = cgroups.GetCgroupRoot()
	args[initArgBpffsRoot] = bpf.GetMapRoot()

	if option.Config.EnableIPv4 {
		args[initArgIPv4NodeIP] = node.GetInternalIPv4().String()
	} else {
		args[initArgIPv4NodeIP] = "<nil>"
	}

	if option.Config.EnableIPv6 {
		args[initArgIPv6NodeIP] = node.GetIPv6().String()
		// Docker <17.05 has an issue which causes IPv6 to be disabled in the initns for all
		// interface (https://github.com/docker/libnetwork/issues/1720)
		// Enable IPv6 for now
		sysSettings = append(sysSettings,
			setting{"net.ipv6.conf.all.disable_ipv6", "0", false})
	} else {
		args[initArgIPv6NodeIP] = "<nil>"
	}

	args[initArgMTU] = fmt.Sprintf("%d", d.mtuConfig.GetDeviceMTU())

	if option.Config.EnableIPSec {
		args[initArgIPSec] = "true"
	} else {
		args[initArgIPSec] = "false"
	}

	if !option.Config.InstallIptRules && option.Config.Masquerade {
		args[initArgMasquerade] = "true"
	} else {
		args[initArgMasquerade] = "false"
	}

	if option.Config.EnableHostReachableServices {
		args[initArgHostReachableServices] = "true"
		if option.Config.EnableHostServicesUDP {
			args[initArgHostReachableServicesUDP] = "true"
		} else {
			args[initArgHostReachableServicesUDP] = "false"
		}
	} else {
		args[initArgHostReachableServices] = "false"
		args[initArgHostReachableServicesUDP] = "false"
	}

	if option.Config.EncryptInterface != "" {
		args[initArgEncryptInterface] = option.Config.EncryptInterface
	}

	if option.Config.Device != "undefined" {
		_, err := netlink.LinkByName(option.Config.Device)
		if err != nil {
			log.WithError(err).WithField("device", option.Config.Device).Warn("Link does not exist")
			return err
		}

		if option.Config.IsLBEnabled() {
			if option.Config.Device != option.Config.LBInterface {
				//FIXME: allow different interfaces
				return fmt.Errorf("Unable to have an interface for LB mode different than snooping interface")
			}
			if err := d.setHostAddresses(); err != nil {
				return err
			}
			mode = "lb"
		} else {
			if option.Config.DatapathMode == option.DatapathModeIpvlan {
				mode = "ipvlan"
			} else {
				mode = "direct"
			}
		}

		args[initArgMode] = mode
		if option.Config.EnableNodePort &&
			strings.ToLower(option.Config.Tunnel) != "disabled" {
			args[initArgMode] = option.Config.Tunnel
		}
		args[initArgDevice] = option.Config.Device
	} else {
		if option.Config.IsLBEnabled() && strings.ToLower(option.Config.Tunnel) != "disabled" {
			//FIXME: allow LBMode in tunnel
			return fmt.Errorf("Unable to run LB mode with tunnel mode")
		}

		args[initArgMode] = option.Config.Tunnel

		if option.Config.IsFlannelMasterDeviceSet() {
			args[initArgMode] = "flannel"
			args[initArgDevice] = option.Config.FlannelMasterDevice
		}
	}

	if option.Config.EnableEndpointRoutes == true {
		args[initArgMode] = "routed"
	}

	if option.Config.EnableNodePort {
		args[initArgNodePort] = "true"
	}

	log.Info("Setting up base BPF datapath")

	for _, s := range sysSettings {
		log.Infof("Setting sysctl %s=%s", s.name, s.val)
		if err := sysctl.Write(s.name, s.val); err != nil {
			if !s.ignoreErr {
				return fmt.Errorf("Failed to sysctl -w %s=%s: %s", s.name, s.val, err)
			}
			log.WithError(err).WithFields(logrus.Fields{
				logfields.SysParamName:  s.name,
				logfields.SysParamValue: s.val,
			}).Warning("Failed to sysctl -w")
		}
	}

	prog := filepath.Join(option.Config.BpfDir, "init.sh")
	ctx, cancel := context.WithTimeout(context.Background(), defaults.ExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Env = bpf.Environment()
	if _, err := cmd.CombinedOutput(log, true); err != nil {
		return err
	}

	if canDisableDwarfRelocations {
		// Validate alignments of C and Go equivalent structs
		if err := alignchecker.CheckStructAlignments(defaults.AlignCheckerName); err != nil {
			log.WithError(err).Fatal("C and Go structs alignment check failed")
		}
	} else {
		log.Warning("Cannot check matching of C and Go common struct alignments due to old LLVM/clang version")
	}

	if !option.Config.IsFlannelMasterDeviceSet() {
		d.ipam.ReserveLocalRoutes()
	}

	if err := d.datapath.Node().NodeConfigurationChanged(d.nodeDiscovery.LocalConfig); err != nil {
		return err
	}

	if option.Config.InstallIptRules {
		if err := d.iptablesManager.TransientRulesStart(option.Config.HostDevice); err != nil {
			return err
		}
	}
	// Always remove masquerade rule and then re-add it if required
	d.iptablesManager.RemoveRules()
	if option.Config.InstallIptRules {
		err := d.iptablesManager.InstallRules(option.Config.HostDevice)
		d.iptablesManager.TransientRulesEnd(false)
		if err != nil {
			return err
		}
	}
	// Reinstall proxy rules for any running proxies
	if d.l7Proxy != nil {
		d.l7Proxy.ReinstallRules()
	}

	return nil
}

func (d *Daemon) createNodeConfigHeaderfile() error {
	nodeConfigPath := option.Config.GetNodeConfigPath()
	f, err := os.Create(nodeConfigPath)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, nodeConfigPath).Fatal("Failed to create node configuration file")
		return err
	}
	defer f.Close()

	if err = d.datapath.WriteNodeConfig(f, &d.nodeDiscovery.LocalConfig); err != nil {
		log.WithError(err).WithField(logfields.Path, nodeConfigPath).Fatal("Failed to write node configuration file")
		return err
	}
	return nil
}

func deleteHostDevice() {
	link, err := netlink.LinkByName(option.Config.HostDevice)
	if err != nil {
		log.WithError(err).Warningf("Unable to lookup host device %s. No old cilium_host interface exists", option.Config.HostDevice)
		return
	}

	if err := netlink.LinkDel(link); err != nil {
		log.WithError(err).Errorf("Unable to delete host device %s to change allocation CIDR", option.Config.HostDevice)
	}
}

// listFilterIfs returns a map of interfaces based on the given filter.
// The filter should take a link and, if found, return the index of that
// interface, if not found return -1.
func listFilterIfs(filter func(netlink.Link) int) (map[int]netlink.Link, error) {
	ifs, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	vethLXCIdxs := map[int]netlink.Link{}
	for _, intf := range ifs {
		if idx := filter(intf); idx != -1 {
			vethLXCIdxs[idx] = intf
		}
	}
	return vethLXCIdxs, nil
}

// clearCiliumVeths checks all veths created by cilium and removes all that
// are considered a leftover from failed attempts to connect the container.
func (d *Daemon) clearCiliumVeths() error {
	log.Info("Removing stale endpoint interfaces")

	leftVeths, err := listFilterIfs(func(intf netlink.Link) int {
		// Filter by veth and return the index of the interface.
		if intf.Type() == "veth" {
			return intf.Attrs().Index
		}
		return -1
	})

	if err != nil {
		return fmt.Errorf("unable to retrieve host network interfaces: %s", err)
	}

	for _, v := range leftVeths {
		peerIndex := v.Attrs().ParentIndex
		parentVeth, found := leftVeths[peerIndex]
		if found && peerIndex != 0 && strings.HasPrefix(parentVeth.Attrs().Name, "lxc") {
			err := netlink.LinkDel(v)
			if err != nil {
				log.WithError(err).Warningf("Unable to delete stale veth device %s", v.Attrs().Name)
			}
		}
	}
	return nil
}

// Must be called with option.Config.EnablePolicyMU locked.
func (d *Daemon) writePreFilterHeader(dir string) error {
	headerPath := filepath.Join(dir, common.PreFilterHeaderFileName)
	log.WithField(logfields.Path, headerPath).Debug("writing configuration")
	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()
	fw := bufio.NewWriter(f)
	fmt.Fprint(fw, "/*\n")
	fmt.Fprintf(fw, " * XDP device: %s\n", option.Config.DevicePreFilter)
	fmt.Fprintf(fw, " * XDP mode: %s\n", option.Config.ModePreFilter)
	fmt.Fprint(fw, " */\n\n")
	d.preFilter.WriteConfig(fw)
	return fw.Flush()
}

func (d *Daemon) writeNetdevHeader(dir string) error {
	headerPath := filepath.Join(dir, common.NetdevHeaderFileName)
	log.WithField(logfields.Path, headerPath).Debug("writing configuration")

	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()

	if err := d.datapath.WriteNetdevConfig(f, d); err != nil {
		return err
	}
	return nil
}

// EndpointMapManager is a wrapper around an endpointmanager as well as the
// filesystem for removing maps related to endpoints from the filesystem.
type EndpointMapManager struct {
	*endpointmanager.EndpointManager
}

// RemoveDatapathMapping unlinks the endpointID from the global policy map, preventing
// packets that arrive on this node from being forwarded to the endpoint that
// used to exist with the specified ID.
func (e *EndpointMapManager) RemoveDatapathMapping(endpointID uint16) error {
	return policymap.RemoveGlobalMapping(uint32(endpointID))
}

// RemoveMapPath removes the specified path from the filesystem.
func (e *EndpointMapManager) RemoveMapPath(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.WithError(err).WithField(logfields.Path, path).Warn("Error while deleting stale map file")
	} else {
		log.WithField(logfields.Path, path).Info("Removed stale bpf map")
	}
}

// waitForHostDeviceWhenReady waits the given ifaceName to be up and ready. If
// ifaceName is not found, then it will wait forever until the device is
// created.
func waitForHostDeviceWhenReady(ifaceName string) error {
	for i := 0; ; i++ {
		if i%10 == 0 {
			log.WithField(logfields.Interface, ifaceName).
				Info("Waiting for the underlying interface to be initialized with containers")
		}
		_, err := netlink.LinkByName(ifaceName)
		if err == nil {
			log.WithField(logfields.Interface, ifaceName).
				Info("Underlying interface initialized with containers!")
			break
		}
		select {
		case <-cleanUPSig:
			return errors.New("clean up signal triggered")
		default:
			time.Sleep(time.Second)
		}
	}
	return nil
}

func endParallelMapMode() {
	ipcachemap.IPCache.EndParallelMode()
}
