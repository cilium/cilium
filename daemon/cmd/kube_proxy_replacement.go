// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This module contains the kube-proxy replacement initialization helpers.

package cmd

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/loader"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/mountinfo"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/sysctl"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// initKubeProxyReplacementOptions will grok the global config and determine
// if we strictly enforce a kube-proxy replacement.
//
// if we determine the config denotes a "strict" kube-proxy replacement, the
// returned boolean will be true, when we detect a "non-strict" configuration the
// return boolean is false.
//
// if this function cannot determine the strictness an error is returned and the boolean
// is false. If an error is returned the boolean is of no meaning.
func initKubeProxyReplacementOptions() error {
	if option.Config.KubeProxyReplacement != option.KubeProxyReplacementStrict &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementPartial &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementDisabled {
		return fmt.Errorf("Invalid value for --%s: %s", option.KubeProxyReplacement, option.Config.KubeProxyReplacement)
	}

	if option.Config.KubeProxyReplacement == option.KubeProxyReplacementDisabled {
		log.Infof("Auto-disabling %q, %q, %q, %q features and falling back to %q",
			option.EnableNodePort, option.EnableExternalIPs,
			option.EnableSocketLB, option.EnableHostPort,
			option.EnableHostLegacyRouting)

		disableNodePort()
		option.Config.EnableSocketLB = false
		option.Config.EnableSocketLBTracing = false

		return nil
	}

	if option.Config.KubeProxyReplacement == option.KubeProxyReplacementStrict {
		log.Infof("Auto-enabling %q, %q, %q, %q, %q features",
			option.EnableNodePort, option.EnableExternalIPs,
			option.EnableSocketLB, option.EnableHostPort,
			option.EnableSessionAffinity)

		option.Config.EnableHostPort = true
		option.Config.EnableNodePort = true
		option.Config.EnableExternalIPs = true
		option.Config.EnableSocketLB = true
		option.Config.EnableSessionAffinity = true
	}

	if option.Config.EnableNodePort {
		if option.Config.EnableIPSec {
			return fmt.Errorf("IPSec cannot be used with BPF NodePort")
		}

		if option.Config.NodePortMode != option.NodePortModeSNAT &&
			option.Config.NodePortMode != option.NodePortModeDSR &&
			option.Config.NodePortMode != option.NodePortModeHybrid {
			return fmt.Errorf("Invalid value for --%s: %s", option.NodePortMode, option.Config.NodePortMode)
		}

		if option.Config.NodePortMode == option.NodePortModeDSR &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchOption &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchIPIP &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchGeneve ||
			option.Config.NodePortMode == option.NodePortModeHybrid &&
				option.Config.LoadBalancerDSRDispatch != option.DSRDispatchOption {
			return fmt.Errorf("Invalid value for --%s: %s", option.LoadBalancerDSRDispatch, option.Config.LoadBalancerDSRDispatch)
		}

		if option.Config.NodePortMode == option.NodePortModeDSR &&
			option.Config.LoadBalancerDSRL4Xlate != option.DSRL4XlateFrontend &&
			option.Config.LoadBalancerDSRL4Xlate != option.DSRL4XlateBackend {
			return fmt.Errorf("Invalid value for --%s: %s", option.LoadBalancerDSRL4Xlate, option.Config.LoadBalancerDSRL4Xlate)
		}

		if option.Config.LoadBalancerRSSv4CIDR != "" {
			ip, cidr, err := net.ParseCIDR(option.Config.LoadBalancerRSSv4CIDR)
			if ip.To4() == nil {
				err = fmt.Errorf("CIDR is not IPv4 based")
			}
			if err == nil {
				if ones, _ := cidr.Mask.Size(); ones == 0 {
					err = fmt.Errorf("CIDR length must be in (0,32]")
				}
			}
			if err != nil {
				return fmt.Errorf("Invalid value for --%s: %s",
					option.LoadBalancerRSSv4CIDR, option.Config.LoadBalancerRSSv4CIDR)
			}
			option.Config.LoadBalancerRSSv4 = *cidr
		}

		if option.Config.LoadBalancerRSSv6CIDR != "" {
			ip, cidr, err := net.ParseCIDR(option.Config.LoadBalancerRSSv6CIDR)
			if ip.To4() != nil {
				err = fmt.Errorf("CIDR is not IPv6 based")
			}
			if err == nil {
				if ones, _ := cidr.Mask.Size(); ones == 0 {
					err = fmt.Errorf("CIDR length must be in (0,128]")
				}
			}
			if err != nil {
				return fmt.Errorf("Invalid value for --%s: %s",
					option.LoadBalancerRSSv6CIDR, option.Config.LoadBalancerRSSv6CIDR)
			}
			option.Config.LoadBalancerRSSv6 = *cidr
		}

		if (option.Config.LoadBalancerRSSv4CIDR != "" || option.Config.LoadBalancerRSSv6CIDR != "") &&
			(option.Config.NodePortMode != option.NodePortModeDSR ||
				option.Config.LoadBalancerDSRDispatch != option.DSRDispatchIPIP) {
			return fmt.Errorf("Invalid value for --%s/%s: currently only supported under IPIP dispatch for DSR",
				option.LoadBalancerRSSv4CIDR, option.LoadBalancerRSSv6CIDR)
		}

		if option.Config.NodePortAlg != option.NodePortAlgRandom &&
			option.Config.NodePortAlg != option.NodePortAlgMaglev {
			return fmt.Errorf("Invalid value for --%s: %s", option.NodePortAlg, option.Config.NodePortAlg)
		}

		if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled &&
			option.Config.NodePortAcceleration != option.NodePortAccelerationGeneric &&
			option.Config.NodePortAcceleration != option.NodePortAccelerationNative {
			return fmt.Errorf("Invalid value for --%s: %s", option.NodePortAcceleration, option.Config.NodePortAcceleration)
		}

		if !option.Config.NodePortBindProtection {
			log.Warning("NodePort BPF configured without bind(2) protection against service ports")
		}

		if option.Config.NodePortAlg == option.NodePortAlgMaglev {
			// "Let N be the size of a VIP's backend pool." [...] "In practice, we choose M to be
			// larger than 100 x N to ensure at most a 1% difference in hash space assigned to
			// backends." (from Maglev paper, page 6)
			supportedPrimes := []int{251, 509, 1021, 2039, 4093, 8191, 16381, 32749, 65521, 131071}
			found := false
			for _, prime := range supportedPrimes {
				if option.Config.MaglevTableSize == prime {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("Invalid value for --%s: %d, supported values are: %v",
					option.MaglevTableSize, option.Config.MaglevTableSize, supportedPrimes)
			}
			if err := maglev.Init(
				option.Config.MaglevHashSeed,
				uint64(option.Config.MaglevTableSize),
			); err != nil {
				return fmt.Errorf("Failed to initialize maglev hash seeds: %w", err)
			}
		}
	}

	if option.Config.EnableNodePort {
		if option.Config.TunnelingEnabled() && option.Config.TunnelProtocol == option.TunnelVXLAN &&
			option.Config.NodePortMode != option.NodePortModeSNAT {
			return fmt.Errorf("Node Port %q mode cannot be used with %s tunneling.", option.Config.NodePortMode, option.Config.TunnelProtocol)
		}

		if option.Config.TunnelingEnabled() && option.Config.TunnelProtocol == option.TunnelGeneve &&
			option.Config.NodePortMode != option.NodePortModeSNAT &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchGeneve {
			return fmt.Errorf("Node Port %q mode with %s dispatch cannot be used with %s tunneling.",
				option.Config.NodePortMode, option.Config.LoadBalancerDSRDispatch, option.Config.TunnelProtocol)
		}

		if option.Config.NodePortMode == option.NodePortModeDSR &&
			option.Config.LoadBalancerDSRDispatch == option.DSRDispatchGeneve &&
			option.Config.TunnelingEnabled() && option.Config.TunnelProtocol != option.TunnelGeneve {
			return fmt.Errorf("Node Port %q mode with %s dispatch requires %s tunneling.",
				option.Config.NodePortMode, option.Config.LoadBalancerDSRDispatch, option.TunnelGeneve)
		}

		if option.Config.NodePortMode == option.NodePortModeDSR &&
			option.Config.LoadBalancerDSRDispatch == option.DSRDispatchIPIP {
			if option.Config.DatapathMode != datapathOption.DatapathModeLBOnly {
				return fmt.Errorf("DSR dispatch mode %s only supported for --%s=%s", option.Config.LoadBalancerDSRDispatch, option.DatapathMode, datapathOption.DatapathModeLBOnly)
			}
			if option.Config.NodePortAcceleration == option.NodePortAccelerationDisabled {
				return fmt.Errorf("DSR dispatch mode %s currently only available under XDP acceleration", option.Config.LoadBalancerDSRDispatch)
			}
		}

		option.Config.EnableHealthDatapath =
			option.Config.DatapathMode == datapathOption.DatapathModeLBOnly &&
				option.Config.NodePortMode == option.NodePortModeDSR &&
				option.Config.LoadBalancerDSRDispatch == option.DSRDispatchIPIP
	}

	if option.Config.InstallNoConntrackIptRules {
		// InstallNoConntrackIptRules can only be enabled when Cilium is
		// running in full KPR mode as otherwise conntrack would be
		// required for NAT operations
		if !option.Config.KubeProxyReplacementFullyEnabled() {
			return fmt.Errorf("%s requires the agent to run with %s=%s.",
				option.InstallNoConntrackIptRules, option.KubeProxyReplacement, option.KubeProxyReplacementStrict)
		}

		if option.Config.MasqueradingEnabled() && !option.Config.EnableBPFMasquerade {
			return fmt.Errorf("%s requires the agent to run with %s.",
				option.InstallNoConntrackIptRules, option.EnableBPFMasquerade)
		}
	}
	if option.Config.BPFSocketLBHostnsOnly {
		option.Config.EnableSocketLBTracing = false
	}

	if option.Config.DryMode {
		return nil
	}

	return probeKubeProxyReplacementOptions()
}

// probeKubeProxyReplacementOptions checks whether the requested KPR options can be enabled with
// the running kernel.
func probeKubeProxyReplacementOptions() error {
	if option.Config.EnableNodePort {
		if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnFibLookup) != nil {
			return fmt.Errorf("BPF NodePort services needs kernel 4.17.0 or newer")
		}

		if err := checkNodePortAndEphemeralPortRanges(); err != nil {
			return err
		}

		if option.Config.EnableRecorder {
			if probes.HaveProgramHelper(ebpf.XDP, asm.FnKtimeGetBootNs) != nil {
				return fmt.Errorf("pcap recorder --%s datapath needs kernel 5.8.0 or newer", option.EnableRecorder)
			}
		}

		if option.Config.EnableHealthDatapath {
			if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetsockopt) != nil {
				option.Config.EnableHealthDatapath = false
				log.Info("BPF load-balancer health check datapath needs kernel 5.12.0 or newer. Disabling BPF load-balancer health check datapath.")
			}
		}
	}

	if option.Config.EnableSocketLB {
		if err := probes.HaveAttachCgroup(); err != nil {
			return fmt.Errorf("socketlb enabled, but kernel does not support attaching bpf programs to cgroups: %w", err)
		}

		// Try to auto-load IPv6 module if it hasn't been done yet as there can
		// be v4-in-v6 connections even if the agent has v6 support disabled.
		probes.HaveIPv6Support()

		if option.Config.EnableMKE {
			if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetCgroupClassid) != nil ||
				probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetNetnsCookie) != nil {
				log.Fatalf("BPF kube-proxy replacement under MKE with --%s needs kernel 5.7 or newer", option.EnableMKE)
			}
		}

		option.Config.EnableSocketLBPeer = true
		if option.Config.EnableIPv4 {
			if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCgroupInet4GetPeername); err != nil {
				option.Config.EnableSocketLBPeer = false
			}
			if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCGroupInet4Connect); err != nil {
				return fmt.Errorf("BPF host-reachable services for TCP needs kernel 4.17.0 or newer: %w", err)
			}
			if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCGroupUDP4Recvmsg); err != nil {
				return fmt.Errorf("BPF host-reachable services for UDP needs kernel 4.19.57, 5.1.16, 5.2.0 or newer: %w", err)
			}
		}

		if option.Config.EnableIPv6 {
			if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCgroupInet6GetPeername); err != nil {
				option.Config.EnableSocketLBPeer = false
			}
			if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCGroupInet6Connect); err != nil {
				return fmt.Errorf("BPF host-reachable services for TCP needs kernel 4.17.0 or newer: %w", err)
			}
			if err := probes.HaveAttachType(ebpf.CGroupSockAddr, ebpf.AttachCGroupUDP6Recvmsg); err != nil {
				return fmt.Errorf("BPF host-reachable services for UDP needs kernel 4.19.57, 5.1.16, 5.2.0 or newer: %w", err)
			}
		}

		if !option.Config.EnableSocketLB {
			option.Config.EnableSocketLBTracing = false
		}
		if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnPerfEventOutput) != nil {
			option.Config.EnableSocketLBTracing = false
			log.Warn("Disabling socket-LB tracing as it requires kernel 5.7 or newer")
		}
	} else {
		option.Config.EnableSocketLBTracing = false
	}

	if option.Config.EnableSessionAffinity && option.Config.EnableSocketLB {
		if probes.HaveProgramHelper(ebpf.CGroupSock, asm.FnGetNetnsCookie) != nil ||
			probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetNetnsCookie) != nil {
			log.Warn("Session affinity for host reachable services needs kernel 5.7.0 or newer " +
				"to work properly when accessed from inside cluster: the same service endpoint " +
				"will be selected from all network namespaces on the host.")
		}
	}

	if option.Config.BPFSocketLBHostnsOnly {
		if !option.Config.EnableSocketLB {
			option.Config.BPFSocketLBHostnsOnly = false
			log.Warnf("%s only takes effect when %s is true", option.BPFSocketLBHostnsOnly, option.EnableSocketLB)
		} else if probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetNetnsCookie) != nil {
			option.Config.BPFSocketLBHostnsOnly = false
			log.Warn("Without network namespace cookie lookup functionality, BPF datapath " +
				"cannot distinguish root and non-root namespace, skipping socket-level " +
				"loadbalancing will not work. Istio routing chains will be missed. " +
				"Needs kernel version >= 5.7")
		}
	}

	return nil
}

// finishKubeProxyReplacementInit finishes initialization of kube-proxy
// replacement after all devices are known.
func finishKubeProxyReplacementInit() error {
	if !(option.Config.EnableNodePort || option.Config.EnableWireguard) {
		// Make sure that NodePort dependencies are disabled
		disableNodePort()
		return nil
	}

	if option.Config.DryMode {
		return nil
	}

	if err := node.InitNodePortAddrs(option.Config.GetDevices(), option.Config.LBDevInheritIPAddr); err != nil {
		msg := "failed to initialize NodePort addrs."
		return fmt.Errorf(msg+" : %w", err)
	}

	// +-------------------------------------------------------+
	// | After this point, BPF NodePort should not be disabled |
	// +-------------------------------------------------------+

	// When WG & encrypt-node are on, a NodePort BPF to-be forwarded request
	// to a remote node running a selected service endpoint must be encrypted.
	// To make the NodePort's rev-{S,D}NAT translations to happen for a reply
	// from the remote node, we need to attach bpf_host to the Cilium's WG
	// netdev (otherwise, the WG netdev after decrypting the reply will pass
	// it to the stack which drops the packet).
	if option.Config.EnableNodePort &&
		option.Config.EnableWireguard && option.Config.EncryptNode {
		option.Config.AppendDevice(wgTypes.IfaceName)
	}

	// For MKE, we only need to change/extend the socket LB behavior in case
	// of kube-proxy replacement. Otherwise, nothing else is needed.
	if option.Config.EnableMKE && option.Config.EnableSocketLB {
		markHostExtension()
	}

	if !option.Config.EnableHostLegacyRouting {
		msg := ""
		switch {
		// Needs host stack for packet handling.
		case option.Config.EnableIPSec:
			msg = fmt.Sprintf("BPF host routing is incompatible with %s.", option.EnableIPSecName)
		// Non-BPF masquerade requires netfilter and hence CT.
		case option.Config.IptablesMasqueradingEnabled():
			msg = fmt.Sprintf("BPF host routing requires %s.", option.EnableBPFMasquerade)
		// KPR=strict is needed or we might rely on netfilter.
		case option.Config.KubeProxyReplacement != option.KubeProxyReplacementStrict:
			msg = fmt.Sprintf("BPF host routing requires %s=%s.", option.KubeProxyReplacement, option.KubeProxyReplacementStrict)
		// All cases below still need to be implemented ...
		case option.Config.EnableEndpointRoutes && option.Config.EnableIPv6:
			msg = fmt.Sprintf("BPF host routing is currently not supported with %s when IPv6 is enabled.", option.EnableEndpointRoutes)
		default:
			if probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnRedirectNeigh) != nil ||
				probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnRedirectPeer) != nil {
				msg = fmt.Sprintf("BPF host routing requires kernel 5.10 or newer.")
			}
		}
		if msg != "" {
			option.Config.EnableHostLegacyRouting = true
			log.Infof("%s Falling back to legacy host routing (%s=true).", msg, option.EnableHostLegacyRouting)
		}
	}

	if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled {
		if err := loader.SetXDPMode(option.Config.NodePortAcceleration); err != nil {
			return fmt.Errorf("Cannot set NodePort acceleration: %w", err)
		}
	}

	option.Config.NodePortNat46X64 = option.Config.EnableIPv4 && option.Config.EnableIPv6 &&
		option.Config.NodePortMode == option.NodePortModeSNAT &&
		probes.HaveLargeInstructionLimit() == nil

	for _, iface := range option.Config.GetDevices() {
		link, err := netlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("Cannot retrieve %s link: %w", iface, err)
		}
		if strings.ContainsAny(iface, "=;") {
			// Because we pass IPV{4,6}_NODEPORT addresses to bpf/init.sh
			// in a form "$IFACE_NAME1=$IPV{4,6}_ADDR1;$IFACE_NAME2=...",
			// we need to restrict the iface names. Otherwise, bpf/init.sh
			// won't properly parse the mappings.
			return fmt.Errorf("%s link name contains '=' or ';' character which is not allowed",
				iface)
		}
		if idx := link.Attrs().Index; idx > math.MaxUint16 {
			return fmt.Errorf("%s link ifindex %d exceeds max(uint16)", iface, idx)
		}
	}

	if option.Config.EnableIPv4 &&
		!option.Config.TunnelingEnabled() &&
		option.Config.NodePortMode != option.NodePortModeSNAT &&
		len(option.Config.GetDevices()) > 1 {

		// In the case of the multi-dev NodePort DSR, if a request from an
		// external client was sent to a device which is not used for direct
		// routing, such request might be dropped by the destination node
		// if the destination node's direct routing device's rp_filter = 1
		// and the client IP is reachable via other device than the direct
		// routing one.

		iface := option.Config.DirectRoutingDevice
		if val, err := sysctl.Read(fmt.Sprintf("net.ipv4.conf.%s.rp_filter", iface)); err != nil {
			log.Warnf("Unable to read net.ipv4.conf.%s.rp_filter: %s. Ignoring the check",
				iface, err)
		} else {
			if val == "1" {
				log.Warnf(`DSR might not work for requests sent to other than %s device. `+
					`Run 'sysctl -w net.ipv4.conf.%s.rp_filter=2' (or set to '0') on each node to fix`,
					iface, iface)
			}
		}
	}

	return nil
}

// disableNodePort disables BPF NodePort and friends who are dependent from
// the latter.
func disableNodePort() {
	option.Config.EnableNodePort = false
	option.Config.EnableHostPort = false
	option.Config.EnableExternalIPs = false
	option.Config.EnableSVCSourceRangeCheck = false
	option.Config.EnableHostLegacyRouting = true
}

// markHostExtension tells the socket LB that MKE managed containers belong
// to the "hostns" as well despite them residing in their own netns. We use
// net_cls as a marker.
func markHostExtension() {
	prefix := option.Config.CgroupPathMKE
	if prefix == "" {
		mountInfos, err := mountinfo.GetMountInfo()
		if err != nil {
			log.WithError(err).Fatal("Cannot retrieve mount infos for MKE")
		}
		for _, mountInfo := range mountInfos {
			if mountInfo.FilesystemType == "cgroup" &&
				strings.Contains(mountInfo.SuperOptions, "net_cls") {
				// There can be multiple entries with the same mountpoint.
				// Assert that there is no conflict.
				if prefix != "" && prefix != mountInfo.MountPoint {
					log.Fatalf("Multiple cgroup v1 net_cls mounts: %s, %s",
						prefix, mountInfo.MountPoint)
				}
				prefix = mountInfo.MountPoint
			}
		}
	}
	if prefix == "" {
		log.Fatal("Cannot retrieve cgroup v1 net_cls mount info for MKE")
	}
	log.WithField(logfields.Path, prefix).Info("Found cgroup v1 net_cls mount on MKE")
	err := filepath.Walk(prefix,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() || strings.Contains(path, "kubepods") || path == prefix {
				return nil
			}
			log.WithField(logfields.Path, path).Info("Marking as MKE host extension")
			f, err := os.OpenFile(path+"/net_cls.classid", os.O_RDWR, 0644)
			if err != nil {
				return err
			}
			defer f.Close()
			valBytes, err := safeio.ReadAllLimit(f, safeio.KB)
			if err != nil {
				return err
			}
			class, err := strconv.Atoi(string(valBytes[:len(valBytes)-1]))
			if err != nil {
				return err
			}
			if class != 0 && class != option.HostExtensionMKE {
				return errors.New("net_cls.classid already in use")
			}
			_, err = io.WriteString(f, fmt.Sprintf("%d", option.HostExtensionMKE))
			return err
		})
	if err != nil {
		log.WithError(err).Fatal("Cannot mark MKE-related container")
	}
}

// checkNodePortAndEphemeralPortRanges checks whether the ephemeral port range
// does not clash with the nodeport range to prevent the BPF nodeport from
// hijacking an existing connection on the local host which source port is
// the same as a nodeport service.
//
// If it clashes, check whether the nodeport range is listed in ip_local_reserved_ports.
// If it isn't and EnableAutoProtectNodePortRange == false, then return an error
// making cilium-agent to stop.
// Otherwise, if EnableAutoProtectNodePortRange == true, then append the nodeport
// range to ip_local_reserved_ports.
func checkNodePortAndEphemeralPortRanges() error {
	ephemeralPortRangeStr, err := sysctl.Read("net.ipv4.ip_local_port_range")
	if err != nil {
		return fmt.Errorf("Unable to read net.ipv4.ip_local_port_range: %w", err)
	}
	ephemeralPortRange := strings.Split(ephemeralPortRangeStr, "\t")
	if len(ephemeralPortRange) != 2 {
		return fmt.Errorf("Invalid ephemeral port range: %s", ephemeralPortRangeStr)
	}
	ephemeralPortMin, err := strconv.Atoi(ephemeralPortRange[0])
	if err != nil {
		return fmt.Errorf("Unable to parse min port value %s for ephemeral range: %w",
			ephemeralPortRange[0], err)
	}
	ephemeralPortMax, err := strconv.Atoi(ephemeralPortRange[1])
	if err != nil {
		return fmt.Errorf("Unable to parse max port value %s for ephemeral range: %w",
			ephemeralPortRange[1], err)
	}

	if option.Config.NodePortMax < ephemeralPortMin {
		// ephemeral port range does not clash with nodeport range
		return nil
	}

	nodePortRangeStr := fmt.Sprintf("%d-%d", option.Config.NodePortMin,
		option.Config.NodePortMax)

	if option.Config.NodePortMin > ephemeralPortMax {
		return fmt.Errorf("NodePort port range (%s) is not allowed to be after ephemeral port range (%s)",
			nodePortRangeStr, ephemeralPortRangeStr)
	}

	reservedPortsStr, err := sysctl.Read("net.ipv4.ip_local_reserved_ports")
	if err != nil {
		return fmt.Errorf("Unable to read net.ipv4.ip_local_reserved_ports: %w", err)
	}
	for _, portRange := range strings.Split(reservedPortsStr, ",") {
		if portRange == "" {
			break
		}
		ports := strings.Split(portRange, "-")
		if len(ports) == 0 {
			return fmt.Errorf("Invalid reserved ports range")
		}
		from, err := strconv.Atoi(ports[0])
		if err != nil {
			return fmt.Errorf("Unable to parse reserved port %q: %w", ports[0], err)
		}
		to := from
		if len(ports) == 2 {
			if to, err = strconv.Atoi(ports[1]); err != nil {
				return fmt.Errorf("Unable to parse reserved port %q", ports[1])
			}
		}

		if from <= option.Config.NodePortMin && to >= option.Config.NodePortMax {
			// nodeport range is protected by reserved port range
			return nil
		}

		if from > option.Config.NodePortMax {
			break
		}
	}

	if !option.Config.EnableAutoProtectNodePortRange {
		msg := `NodePort port range (%s) must not clash with ephemeral port range (%s). ` +
			`Adjust ephemeral range port with "sysctl -w net.ipv4.ip_local_port_range='MIN MAX'", or ` +
			`protect the NodePort range by appending it to "net.ipv4.ip_local_reserved_ports", or ` +
			`set --%s=true to auto-append the range to "net.ipv4.ip_local_reserved_ports"`
		return fmt.Errorf(msg, nodePortRangeStr, ephemeralPortRangeStr,
			option.EnableAutoProtectNodePortRange)
	}

	if reservedPortsStr != "" {
		reservedPortsStr += ","
	}
	reservedPortsStr += fmt.Sprintf("%d-%d", option.Config.NodePortMin, option.Config.NodePortMax)
	if err := sysctl.Write("net.ipv4.ip_local_reserved_ports", reservedPortsStr); err != nil {
		return fmt.Errorf("Unable to addend nodeport range (%s) to net.ipv4.ip_local_reserved_ports: %w",
			nodePortRangeStr, err)
	}

	return nil
}
