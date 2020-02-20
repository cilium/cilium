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

package loader

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/alignchecker"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const (
	initArgLib int = iota
	initArgRundir
	initArgIPv4NodeIP
	initArgIPv6NodeIP
	initArgMode
	initArgDevice
	initArgDevicePreFilter
	initArgModePreFilter
	initArgMTU
	initArgIPSec
	initArgMasquerade
	initArgEncryptInterface
	initArgHostReachableServices
	initArgHostReachableServicesUDP
	initArgCgroupRoot
	initArgBpffsRoot
	initArgNodePort
	initArgMax
)

func (l *Loader) writeNetdevHeader(dir string, o datapath.BaseProgramOwner) error {
	headerPath := filepath.Join(dir, common.NetdevHeaderFileName)
	log.WithField(logfields.Path, headerPath).Debug("writing configuration")

	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()

	if err := l.templateCache.WriteNetdevConfig(f, o); err != nil {
		return err
	}
	return nil
}

// Must be called with option.Config.EnablePolicyMU locked.
func writePreFilterHeader(preFilter *prefilter.PreFilter, dir string) error {
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
	preFilter.WriteConfig(fw)
	return fw.Flush()
}

// Reinitialize (re-)configures the base datapath configuration including global
// BPF programs, netfilter rule configuration and reserving routes in IPAM for
// locally detected prefixes. It may be run upon initial Cilium startup, after
// restore from a previous Cilium run, or during regular Cilium operation.
func (l *Loader) Reinitialize(ctx context.Context, o datapath.BaseProgramOwner, deviceMTU int, iptMgr datapath.IptablesManager, p datapath.Proxy, r datapath.RouteReserver) error {
	var (
		args []string
		mode string
		ret  error
	)

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
	o.GetCompilationLock().Lock()
	defer o.GetCompilationLock().Unlock()

	l.init(o.Datapath(), o.LocalConfig())

	if err := l.writeNetdevHeader("./", o); err != nil {
		log.WithError(err).Warn("Unable to write netdev header")
		return err
	}

	scopedLog := log.WithField(logfields.XDPDevice, option.Config.DevicePreFilter)
	if option.Config.DevicePreFilter != "undefined" {
		if err := prefilter.ProbePreFilter(option.Config.DevicePreFilter, option.Config.ModePreFilter); err != nil {
			scopedLog.WithError(err).Warn("Turning off prefilter")
			option.Config.DevicePreFilter = "undefined"
		}
	}
	if option.Config.DevicePreFilter != "undefined" {
		preFilter, err := prefilter.NewPreFilter()
		if err != nil {
			scopedLog.WithError(ret).Warn("Unable to init prefilter")
			return ret
		}

		if err := writePreFilterHeader(preFilter, "./"); err != nil {
			scopedLog.WithError(err).Warn("Unable to write prefilter header")
			return err
		}

		o.SetPrefilter(preFilter)

		args[initArgDevicePreFilter] = option.Config.DevicePreFilter
		args[initArgModePreFilter] = option.Config.ModePreFilter
	} else {
		args[initArgDevicePreFilter] = "<nil>"
		args[initArgModePreFilter] = "<nil>"
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

	args[initArgMTU] = fmt.Sprintf("%d", deviceMTU)

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
	} else {
		args[initArgEncryptInterface] = "<nil>"
	}

	if option.Config.Device != "undefined" {
		_, err := netlink.LinkByName(option.Config.Device)
		if err != nil {
			log.WithError(err).WithField("device", option.Config.Device).Warn("Link does not exist")
			return err
		}

		if option.Config.DatapathMode == option.DatapathModeIpvlan {
			mode = "ipvlan"
		} else {
			mode = "direct"
		}

		args[initArgMode] = mode
		if option.Config.EnableNodePort &&
			strings.ToLower(option.Config.Tunnel) != "disabled" {
			args[initArgMode] = option.Config.Tunnel
		}
		args[initArgDevice] = option.Config.Device
	} else {
		args[initArgMode] = option.Config.Tunnel
		args[initArgDevice] = "<nil>"

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
	} else {
		args[initArgNodePort] = "false"
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

	for i, arg := range args {
		if arg == "" {
			log.Warningf("empty argument passed to bpf/init.sh at position %d", i)
		}
	}

	prog := filepath.Join(option.Config.BpfDir, "init.sh")
	ctx, cancel := context.WithTimeout(ctx, defaults.ExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Env = bpf.Environment()
	if _, err := cmd.CombinedOutput(log, true); err != nil {
		return err
	}

	if l.canDisableDwarfRelocations {
		// Validate alignments of C and Go equivalent structs
		if err := alignchecker.CheckStructAlignments(defaults.AlignCheckerName); err != nil {
			log.WithError(err).Fatal("C and Go structs alignment check failed")
		}
	} else {
		log.Warning("Cannot check matching of C and Go common struct alignments due to old LLVM/clang version")
	}

	if !option.Config.IsFlannelMasterDeviceSet() {
		r.ReserveLocalRoutes()
	}

	if err := o.Datapath().Node().NodeConfigurationChanged(*o.LocalConfig()); err != nil {
		return err
	}

	if option.Config.InstallIptRules {
		if err := iptMgr.TransientRulesStart(option.Config.HostDevice); err != nil {
			return err
		}
	}
	// Always remove masquerade rule and then re-add it if required
	iptMgr.RemoveRules()
	if option.Config.InstallIptRules {
		err := iptMgr.InstallRules(option.Config.HostDevice)
		iptMgr.TransientRulesEnd(false)
		if err != nil {
			return err
		}
	}
	// Reinstall proxy rules for any running proxies
	if p != nil {
		p.ReinstallRules()
	}

	return nil
}
