// Copyright 2016-2020 Authors of Cilium
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
	"reflect"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/alignchecker"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
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
	initArgDevices
	initArgXDPDevice
	initArgXDPMode
	initArgMTU
	initArgIPSec
	initArgEncryptInterface
	initArgHostReachableServices
	initArgHostReachableServicesUDP
	initArgHostReachableServicesPeer
	initArgCgroupRoot
	initArgBpffsRoot
	initArgNodePort
	initArgNodePortBind
	initBPFCPU
	initArgNodePortIPv4Addrs
	initArgNodePortIPv6Addrs
	initArgNrCPUs
	initArgMax
)

// firstInitialization is true when Reinitialize() is called for the first
// time. It can only be accessed when GetCompilationLock() is being held.
var firstInitialization = true

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
func (l *Loader) Reinitialize(ctx context.Context, o datapath.BaseProgramOwner, deviceMTU int, iptMgr datapath.IptablesManager, p datapath.Proxy) error {
	var (
		args []string
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
		{"kernel.timer_migration", "0", true},
	}

	// Lock so that endpoints cannot be built while we are compile base programs.
	o.GetCompilationLock().Lock()
	defer o.GetCompilationLock().Unlock()
	defer func() { firstInitialization = false }()

	l.init(o.Datapath(), o.LocalConfig())

	if err := l.writeNetdevHeader("./", o); err != nil {
		log.WithError(err).Warn("Unable to write netdev header")
		return err
	}

	if option.Config.XDPDevice != "undefined" {
		args[initArgXDPDevice] = option.Config.XDPDevice
		args[initArgXDPMode] = option.Config.XDPMode
	} else {
		args[initArgXDPDevice] = "<nil>"
		args[initArgXDPMode] = "<nil>"
	}

	if option.Config.DevicePreFilter != "undefined" {
		scopedLog := log.WithField(logfields.XDPDevice, option.Config.XDPDevice)

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

	if option.Config.EnableHostReachableServices {
		args[initArgHostReachableServices] = "true"
		if option.Config.EnableHostServicesUDP {
			args[initArgHostReachableServicesUDP] = "true"
		} else {
			args[initArgHostReachableServicesUDP] = "false"
		}
		if option.Config.EnableHostServicesPeer {
			args[initArgHostReachableServicesPeer] = "true"
		} else {
			args[initArgHostReachableServicesPeer] = "false"
		}
	} else {
		args[initArgHostReachableServices] = "false"
		args[initArgHostReachableServicesUDP] = "false"
		args[initArgHostReachableServicesPeer] = "false"
	}

	if option.Config.EncryptInterface != "" {
		args[initArgEncryptInterface] = option.Config.EncryptInterface
	} else {
		args[initArgEncryptInterface] = "<nil>"
	}

	if len(option.Config.Devices) != 0 {
		for _, device := range option.Config.Devices {
			_, err := netlink.LinkByName(device)
			if err != nil {
				log.WithError(err).WithField("device", device).Warn("Link does not exist")
				return err
			}
		}
		args[initArgDevices] = strings.Join(option.Config.Devices, ";")
	} else if option.Config.IsFlannelMasterDeviceSet() {
		args[initArgDevices] = option.Config.FlannelMasterDevice
	} else {
		args[initArgDevices] = "<nil>"
	}

	switch {
	case option.Config.EnableEndpointRoutes:
		args[initArgMode] = "routed"
	case option.Config.IsFlannelMasterDeviceSet():
		args[initArgMode] = "flannel"
	case option.Config.Tunnel != option.TunnelDisabled:
		args[initArgMode] = option.Config.Tunnel
	case option.Config.DatapathMode == datapathOption.DatapathModeIpvlan:
		args[initArgMode] = "ipvlan"
	default:
		args[initArgMode] = "direct"
	}

	if option.Config.EnableNodePort {
		args[initArgNodePort] = "true"
		if option.Config.EnableIPv4 {
			addrs := node.GetNodePortIPv4AddrsWithDevices()
			tmp := make([]string, 0, len(addrs))
			for iface, ipv4 := range addrs {
				tmp = append(tmp,
					fmt.Sprintf("%s=%#x", iface,
						byteorder.HostSliceToNetwork(ipv4, reflect.Uint32).(uint32)))
			}
			args[initArgNodePortIPv4Addrs] = strings.Join(tmp, ";")
		} else {
			args[initArgNodePortIPv4Addrs] = "<nil>"
		}
		if option.Config.EnableIPv6 {
			addrs := node.GetNodePortIPv6AddrsWithDevices()
			tmp := make([]string, 0, len(addrs))
			for iface, ipv6 := range addrs {
				tmp = append(tmp, fmt.Sprintf("%s=%s", iface, common.GoArray2CNoSpaces(ipv6)))
			}
			args[initArgNodePortIPv6Addrs] = strings.Join(tmp, ";")
		} else {
			args[initArgNodePortIPv6Addrs] = "<nil>"
		}
	} else {
		args[initArgNodePort] = "false"
		args[initArgNodePortIPv4Addrs] = "<nil>"
		args[initArgNodePortIPv6Addrs] = "<nil>"
	}

	if option.Config.NodePortBindProtection {
		args[initArgNodePortBind] = "true"
	} else {
		args[initArgNodePortBind] = "false"
	}

	args[initBPFCPU] = GetBPFCPU()
	args[initArgNrCPUs] = fmt.Sprintf("%d", common.GetNumPossibleCPUs(log))

	clockSource := []string{"ktime", "jiffies"}
	log.WithFields(logrus.Fields{
		logfields.BPFInsnSet:     args[initBPFCPU],
		logfields.BPFClockSource: clockSource[option.Config.ClockSource],
	}).Info("Setting up BPF datapath")

	// AWS ENI mode requires symmetric routing, see
	// iptables.addCiliumENIRules().
	// The default AWS daemonset installs the following rules that are used
	// for NodePort traffic between nodes:
	//
	// # sysctl -w net.ipv4.conf.eth0.rp_filter=2
	// # iptables -t mangle -A PREROUTING -i eth0 -m comment --comment "AWS, primary ENI" -m addrtype --dst-type LOCAL --limit-iface-in -j CONNMARK --set-xmark 0x80/0x80
	// # iptables -t mangle -A PREROUTING -i eni+ -m comment --comment "AWS, primary ENI" -j CONNMARK --restore-mark --nfmask 0x80 --ctmask 0x80
	// # ip rule add fwmark 0x80/0x80 lookup main
	//
	// It marks packets coming from another node through eth0, and restores
	// the mark on the return path to force a lookup into the main routing
	// table. Without these rules, the "ip rules" set by the cilium-cni
	// plugin tell the host to lookup into the table related to the VPC for
	// which the CIDR used by the endpoint has been configured.
	//
	// We want to reproduce equivalent rules to ensure correct routing.
	if option.Config.IPAM == ipamOption.IPAMENI {
		sysSettings = append(sysSettings, setting{"net.ipv4.conf.eth0.rp_filter", "2", false})
		if err := route.ReplaceRule(route.Rule{
			Priority: linux_defaults.RulePriorityNodeport,
			Mark:     linux_defaults.MarkMultinodeNodeport,
			Mask:     linux_defaults.MaskMultinodeNodeport,
			Table:    route.MainTable,
		}); err != nil {
			return fmt.Errorf("unable to install ip rule for ENI multi-node NodePort: %w", err)
		}
	}

	for _, s := range sysSettings {
		log.WithFields(logrus.Fields{
			logfields.SysParamName:  s.name,
			logfields.SysParamValue: s.val,
		}).Info("Setting sysctl")
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

	if err := o.Datapath().Node().NodeConfigurationChanged(*o.LocalConfig()); err != nil {
		return err
	}

	if option.Config.InstallIptRules {
		if err := iptMgr.TransientRulesStart(option.Config.HostDevice); err != nil {
			log.WithError(err).Warning("failed to install transient iptables rules")
		}
	}
	// The iptables rules are only removed on the first initialization to
	// remove stale rules or when iptables is enabled. The first invocation
	// is silent as rules may not exist.
	if firstInitialization || option.Config.InstallIptRules {
		iptMgr.RemoveRules(firstInitialization)
	}
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
