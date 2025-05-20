// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This module contains the kube-proxy replacement initialization helpers.

package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mountinfo"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/safeio"
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
func initKubeProxyReplacementOptions(logger *slog.Logger, sysctl sysctl.Sysctl, tunnelConfig tunnel.Config, lbConfig loadbalancer.Config) error {
	if option.Config.KubeProxyReplacement != option.KubeProxyReplacementTrue &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementFalse {
		return fmt.Errorf("Invalid value for --%s: %s", option.KubeProxyReplacement, option.Config.KubeProxyReplacement)
	}

	if option.Config.KubeProxyReplacement == option.KubeProxyReplacementTrue {
		logger.Info(fmt.Sprintf(
			"Auto-enabling %q, %q, %q, %q, %q features",
			option.EnableNodePort, option.EnableExternalIPs,
			option.EnableSocketLB, option.EnableHostPort,
			option.EnableSessionAffinity,
		),
		)

		option.Config.EnableHostPort = true
		option.Config.EnableNodePort = true
		option.Config.EnableExternalIPs = true
		option.Config.EnableSocketLB = true
		option.Config.EnableSessionAffinity = true
	}

	if option.Config.EnableNodePort {
		if option.Config.NodePortMode != option.NodePortModeSNAT &&
			option.Config.NodePortMode != option.NodePortModeDSR &&
			option.Config.NodePortMode != option.NodePortModeHybrid {
			return fmt.Errorf("Invalid value for --%s: %s", option.NodePortMode, option.Config.NodePortMode)
		}

		if option.Config.LoadBalancerModeAnnotation &&
			option.Config.NodePortMode == option.NodePortModeHybrid {
			return fmt.Errorf("The value --%s=%s is not supported as default under annotation mode", option.NodePortMode, option.Config.NodePortMode)
		}

		if option.Config.NodePortMode == option.NodePortModeDSR &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchOption &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchIPIP &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchGeneve {
			return fmt.Errorf("Invalid value for --%s: %s", option.LoadBalancerDSRDispatch, option.Config.LoadBalancerDSRDispatch)
		}

		if option.Config.NodePortMode == option.NodePortModeHybrid &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchOption &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchGeneve {
			return fmt.Errorf("Invalid value for --%s: %s", option.LoadBalancerDSRDispatch, option.Config.LoadBalancerDSRDispatch)
		}

		if option.Config.LoadBalancerModeAnnotation &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchIPIP {
			return fmt.Errorf("Invalid value for --%s: %s", option.LoadBalancerDSRDispatch, option.Config.LoadBalancerDSRDispatch)
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

		dsrIPIP := option.Config.LoadBalancerUsesDSR() && option.Config.LoadBalancerDSRDispatch == option.DSRDispatchIPIP
		if dsrIPIP && option.Config.NodePortAcceleration == option.NodePortAccelerationDisabled {
			return fmt.Errorf("DSR dispatch mode %s currently only available under XDP acceleration", option.Config.LoadBalancerDSRDispatch)
		}

		if (option.Config.LoadBalancerRSSv4CIDR != "" || option.Config.LoadBalancerRSSv6CIDR != "") && !dsrIPIP {
			return fmt.Errorf("Invalid value for --%s/%s: currently only supported under %s dispatch for DSR",
				option.LoadBalancerRSSv4CIDR, option.LoadBalancerRSSv6CIDR, option.DSRDispatchIPIP)
		}

		if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled &&
			option.Config.EnableWireguard && option.Config.EncryptNode {
			logger.Warn(
				fmt.Sprintf(
					"With %s: %s and %s, %s enabled, N/S Loadbalancer traffic won't be encrypted "+
						"when an intermediate node redirects a request to another node where a selected backend is running.",
					option.NodePortAcceleration, option.Config.NodePortAcceleration, option.EnableWireguard, option.EncryptNode),
				logfields.Hint,
				"Disable XDP acceleration to encrypt N/S Loadbalancer traffic.")
		}

		if !option.Config.NodePortBindProtection {
			logger.Warn("NodePort BPF configured without bind(2) protection against service ports")
		}

		if option.Config.TunnelingEnabled() && tunnelConfig.UnderlayProtocol() == tunnel.IPv6 &&
			option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled {
			return fmt.Errorf("XDP acceleration cannot be used with an IPv6 underlay")
		}

		if option.Config.TunnelingEnabled() && tunnelConfig.EncapProtocol() == tunnel.VXLAN &&
			option.Config.LoadBalancerUsesDSR() {
			return fmt.Errorf("Node Port %q mode cannot be used with %s tunneling.", option.Config.NodePortMode, tunnel.VXLAN)
		}

		if option.Config.TunnelingEnabled() && option.Config.LoadBalancerUsesDSR() &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchGeneve {
			return fmt.Errorf("Tunnel routing with Node Port %q mode requires %s dispatch.",
				option.Config.NodePortMode, option.DSRDispatchGeneve)
		}

		if option.Config.LoadBalancerUsesDSR() &&
			option.Config.LoadBalancerDSRDispatch == option.DSRDispatchGeneve &&
			tunnelConfig.EncapProtocol() != tunnel.Geneve {
			return fmt.Errorf("Node Port %q mode with %s dispatch requires %s tunnel protocol.",
				option.Config.NodePortMode, option.Config.LoadBalancerDSRDispatch, tunnel.Geneve)
		}

		if option.Config.LoadBalancerIPIPSockMark {
			if !dsrIPIP {
				return fmt.Errorf("Node Port %q mode with IPIP socket mark logic requires %s dispatch.",
					option.Config.NodePortMode, option.DSRDispatchIPIP)
			}
			option.Config.EnableHealthDatapath = true
		}
	}

	if option.Config.InstallNoConntrackIptRules {
		// InstallNoConntrackIptRules can only be enabled when Cilium is
		// running in full KPR mode as otherwise conntrack would be
		// required for NAT operations
		if !option.Config.KubeProxyReplacementFullyEnabled() {
			return fmt.Errorf("%s requires the agent to run with %s=%s.",
				option.InstallNoConntrackIptRules, option.KubeProxyReplacement, option.KubeProxyReplacementTrue)
		}

		if option.Config.MasqueradingEnabled() && !option.Config.EnableBPFMasquerade {
			return fmt.Errorf("%s requires the agent to run with %s.",
				option.InstallNoConntrackIptRules, option.EnableBPFMasquerade)
		}
	}
	if option.Config.BPFSocketLBHostnsOnly {
		option.Config.EnableSocketLBTracing = false
	}

	if !option.Config.EnableSocketLB {
		option.Config.EnableSocketLBTracing = false
		option.Config.EnableSocketLBPeer = false
	}

	if option.Config.DryMode {
		return nil
	}

	return probeKubeProxyReplacementOptions(logger, lbConfig, sysctl)
}

// probeKubeProxyReplacementOptions checks whether the requested KPR options can be enabled with
// the running kernel.
func probeKubeProxyReplacementOptions(logger *slog.Logger, lbConfig loadbalancer.Config, sysctl sysctl.Sysctl) error {
	if option.Config.EnableNodePort {
		if probes.HaveProgramHelper(logger, ebpf.SchedCLS, asm.FnFibLookup) != nil {
			return fmt.Errorf("BPF NodePort services needs kernel 4.17.0 or newer")
		}

		if err := checkNodePortAndEphemeralPortRanges(lbConfig, sysctl); err != nil {
			return err
		}

		if option.Config.EnableRecorder {
			if probes.HaveProgramHelper(logger, ebpf.XDP, asm.FnKtimeGetBootNs) != nil {
				return fmt.Errorf("pcap recorder --%s datapath needs kernel 5.8.0 or newer", option.EnableRecorder)
			}
		}

		if option.Config.EnableHealthDatapath {
			if probes.HaveProgramHelper(logger, ebpf.CGroupSockAddr, asm.FnGetsockopt) != nil {
				option.Config.EnableHealthDatapath = false
				logger.Info("BPF load-balancer health check datapath needs kernel 5.12.0 or newer. Disabling BPF load-balancer health check datapath.")
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
			if probes.HaveProgramHelper(logger, ebpf.CGroupSockAddr, asm.FnGetCgroupClassid) != nil ||
				probes.HaveProgramHelper(logger, ebpf.CGroupSockAddr, asm.FnGetNetnsCookie) != nil {
				logging.Fatal(logger, fmt.Sprintf("BPF kube-proxy replacement under MKE with --%s needs kernel 5.7 or newer", option.EnableMKE))
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

		if option.Config.EnableSocketLBTracing {
			if probes.HaveProgramHelper(logger, ebpf.CGroupSockAddr, asm.FnPerfEventOutput) != nil {
				option.Config.EnableSocketLBTracing = false
				logger.Info("Disabling socket-LB tracing as it requires kernel 5.7 or newer")
			}
		}
	} else {
		option.Config.EnableSocketLBTracing = false
		option.Config.EnableSocketLBPodConnectionTermination = false

		if option.Config.BPFSocketLBHostnsOnly {
			option.Config.BPFSocketLBHostnsOnly = false
			logger.Warn(fmt.Sprintf("%s only takes effect when %s is true", option.BPFSocketLBHostnsOnly, option.EnableSocketLB))
		}
	}

	return nil
}

// finishKubeProxyReplacementInit finishes initialization of kube-proxy
// replacement after all devices are known.
func finishKubeProxyReplacementInit(logger *slog.Logger, sysctl sysctl.Sysctl, devices []*tables.Device, directRoutingDevice string) error {
	if !option.Config.EnableNodePort {
		// Make sure that NodePort dependencies are disabled
		disableNodePort()
		return nil
	}

	if option.Config.DryMode {
		return nil
	}

	// +-------------------------------------------------------+
	// | After this point, BPF NodePort should not be disabled |
	// +-------------------------------------------------------+

	// For MKE, we only need to change/extend the socket LB behavior in case
	// of kube-proxy replacement. Otherwise, nothing else is needed.
	if option.Config.EnableMKE && option.Config.EnableSocketLB {
		markHostExtension(logger)
	}

	if !option.Config.EnableHostLegacyRouting {
		msg := ""
		switch {
		// Non-BPF masquerade requires netfilter and hence CT.
		case option.Config.IptablesMasqueradingEnabled():
			msg = fmt.Sprintf("BPF host routing requires %s.", option.EnableBPFMasquerade)
		// KPR=true is needed or we might rely on netfilter.
		case option.Config.KubeProxyReplacement != option.KubeProxyReplacementTrue:
			msg = fmt.Sprintf("BPF host routing requires %s=%s.", option.KubeProxyReplacement, option.KubeProxyReplacementTrue)
		}
		if msg != "" {
			option.Config.EnableHostLegacyRouting = true
			logger.Info(fmt.Sprintf("%s Falling back to legacy host routing (%s=true).", msg, option.EnableHostLegacyRouting))
		}
	}

	if option.Config.NodePortNat46X64 && option.Config.NodePortMode != option.NodePortModeSNAT {
		return fmt.Errorf("NAT46/NAT64 requires SNAT mode for services")
	}

	if option.Config.EnableIPv4 &&
		!option.Config.TunnelingEnabled() &&
		option.Config.LoadBalancerUsesDSR() &&
		directRoutingDevice != "" &&
		len(devices) > 1 {

		// In the case of the multi-dev NodePort DSR, if a request from an
		// external client was sent to a device which is not used for direct
		// routing, such request might be dropped by the destination node
		// if the destination node's direct routing device's rp_filter = 1
		// and the client IP is reachable via other device than the direct
		// routing one.

		if val, err := sysctl.Read([]string{"net", "ipv4", "conf", directRoutingDevice, "rp_filter"}); err != nil {
			logger.Warn(fmt.Sprintf(
				"Unable to read net.ipv4.conf.%s.rp_filter: %s. Ignoring the check",
				directRoutingDevice, err),
			)
		} else {
			if val == "1" {
				logger.Warn(fmt.Sprintf(`DSR might not work for requests sent to other than %s device. `+
					`Run 'sysctl -w net.ipv4.conf.%s.rp_filter=2' (or set to '0') on each node to fix`,
					directRoutingDevice, directRoutingDevice))
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
func markHostExtension(logger *slog.Logger) {
	prefix := option.Config.CgroupPathMKE
	if prefix == "" {
		mountInfos, err := mountinfo.GetMountInfo()
		if err != nil {
			logging.Fatal(logger, "Cannot retrieve mount infos for MKE", logfields.Error, err)
		}
		for _, mountInfo := range mountInfos {
			if mountInfo.FilesystemType == "cgroup" &&
				strings.Contains(mountInfo.SuperOptions, "net_cls") {
				// There can be multiple entries with the same mountpoint.
				// Assert that there is no conflict.
				if prefix != "" && prefix != mountInfo.MountPoint {
					logging.Fatal(logger, fmt.Sprintf("Multiple cgroup v1 net_cls mounts: %s, %s", prefix, mountInfo.MountPoint))
				}
				prefix = mountInfo.MountPoint
			}
		}
	}
	if prefix == "" {
		logging.Fatal(logger, "Cannot retrieve cgroup v1 net_cls mount info for MKE")
	}
	logger.Info("Found cgroup v1 net_cls mount on MKE", logfields.Path, prefix)
	err := filepath.Walk(prefix,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() || strings.Contains(path, "kubepods") || path == prefix {
				return nil
			}
			logger.Info("Marking as MKE host extension", logfields.Path, path)
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
		logging.Fatal(logger, "Cannot mark MKE-related container", logfields.Error, err)
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
func checkNodePortAndEphemeralPortRanges(lbConfig loadbalancer.Config, sysctl sysctl.Sysctl) error {
	ephemeralPortRangeStr, err := sysctl.Read([]string{"net", "ipv4", "ip_local_port_range"})
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

	if lbConfig.NodePortMax < uint16(ephemeralPortMin) {
		// ephemeral port range does not clash with nodeport range
		return nil
	}

	nodePortRangeStr := fmt.Sprintf("%d-%d", lbConfig.NodePortMin,
		lbConfig.NodePortMax)

	if lbConfig.NodePortMin > uint16(ephemeralPortMax) {
		return fmt.Errorf("NodePort port range (%s) is not allowed to be after ephemeral port range (%s)",
			nodePortRangeStr, ephemeralPortRangeStr)
	}

	reservedPortsStr, err := sysctl.Read([]string{"net", "ipv4", "ip_local_reserved_ports"})
	if err != nil {
		return fmt.Errorf("Unable to read net.ipv4.ip_local_reserved_ports: %w", err)
	}
	for portRange := range strings.SplitSeq(reservedPortsStr, ",") {
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

		if uint16(from) <= lbConfig.NodePortMin && uint16(to) >= lbConfig.NodePortMax {
			// nodeport range is protected by reserved port range
			return nil
		}

		if uint16(from) > lbConfig.NodePortMax {
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
	reservedPortsStr += fmt.Sprintf("%d-%d", lbConfig.NodePortMin, lbConfig.NodePortMax)
	if err := sysctl.Write([]string{"net", "ipv4", "ip_local_reserved_ports"}, reservedPortsStr); err != nil {
		return fmt.Errorf("Unable to addend nodeport range (%s) to net.ipv4.ip_local_reserved_ports: %w",
			nodePortRangeStr, err)
	}

	return nil
}
