// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

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

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/loader"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/mountinfo"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/probe"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
func initKubeProxyReplacementOptions() (bool, error) {
	if option.Config.KubeProxyReplacement != option.KubeProxyReplacementStrict &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementPartial &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementProbe &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementDisabled {
		return false, fmt.Errorf("Invalid value for --%s: %s", option.KubeProxyReplacement, option.Config.KubeProxyReplacement)
	}

	if option.Config.KubeProxyReplacement == option.KubeProxyReplacementDisabled {
		log.Infof("Auto-disabling %q, %q, %q, %q, %q features and falling back to %q",
			option.EnableNodePort, option.EnableExternalIPs,
			option.EnableHostReachableServices, option.EnableHostPort,
			option.EnableSessionAffinity, option.EnableHostLegacyRouting)

		disableNodePort()
		option.Config.EnableHostReachableServices = false
		option.Config.EnableHostServicesTCP = false
		option.Config.EnableHostServicesUDP = false
		option.Config.EnableSessionAffinity = false

		return false, nil
	}

	probesManager := probes.NewProbeManager()

	// strict denotes to panic if any to-be enabled feature cannot be enabled
	strict := option.Config.KubeProxyReplacement != option.KubeProxyReplacementProbe

	if option.Config.KubeProxyReplacement == option.KubeProxyReplacementProbe ||
		option.Config.KubeProxyReplacement == option.KubeProxyReplacementStrict {

		log.Infof("Trying to auto-enable %q, %q, %q, %q, %q features",
			option.EnableNodePort, option.EnableExternalIPs,
			option.EnableHostReachableServices, option.EnableHostPort,
			option.EnableSessionAffinity)

		option.Config.EnableHostPort = true
		option.Config.EnableNodePort = true
		option.Config.EnableExternalIPs = true
		option.Config.EnableHostReachableServices = true
		option.Config.EnableHostServicesTCP = true
		option.Config.EnableHostServicesUDP = true
		option.Config.EnableSessionAffinity = true
	}

	if option.Config.EnableNodePort {
		if option.Config.EnableIPSec {
			msg := "IPSec cannot be used with BPF NodePort."
			if strict {
				return false, fmt.Errorf(msg)
			} else {
				disableNodePort()
				log.Warn(msg + " Disabling BPF NodePort feature.")
			}
		}

		if option.Config.NodePortMode != option.NodePortModeSNAT &&
			option.Config.NodePortMode != option.NodePortModeDSR &&
			option.Config.NodePortMode != option.NodePortModeHybrid {
			return false, fmt.Errorf("Invalid value for --%s: %s", option.NodePortMode, option.Config.NodePortMode)
		}

		if option.Config.NodePortMode == option.NodePortModeDSR &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchOption &&
			option.Config.LoadBalancerDSRDispatch != option.DSRDispatchIPIP ||
			option.Config.NodePortMode == option.NodePortModeHybrid &&
				option.Config.LoadBalancerDSRDispatch != option.DSRDispatchOption {
			return false, fmt.Errorf("Invalid value for --%s: %s", option.LoadBalancerDSRDispatch, option.Config.LoadBalancerDSRDispatch)
		}

		if option.Config.NodePortMode == option.NodePortModeDSR &&
			option.Config.LoadBalancerDSRL4Xlate != option.DSRL4XlateFrontend &&
			option.Config.LoadBalancerDSRL4Xlate != option.DSRL4XlateBackend {
			return false, fmt.Errorf("Invalid value for --%s: %s", option.LoadBalancerDSRL4Xlate, option.Config.LoadBalancerDSRL4Xlate)
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
				return false, fmt.Errorf("Invalid value for --%s: %s",
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
				return false, fmt.Errorf("Invalid value for --%s: %s",
					option.LoadBalancerRSSv6CIDR, option.Config.LoadBalancerRSSv6CIDR)
			}
			option.Config.LoadBalancerRSSv6 = *cidr
		}

		if (option.Config.LoadBalancerRSSv4CIDR != "" || option.Config.LoadBalancerRSSv6CIDR != "") &&
			(option.Config.NodePortMode != option.NodePortModeDSR ||
				option.Config.LoadBalancerDSRDispatch != option.DSRDispatchIPIP) {
			return false, fmt.Errorf("Invalid value for --%s/%s: currently only supported under IPIP dispatch for DSR",
				option.LoadBalancerRSSv4CIDR, option.LoadBalancerRSSv6CIDR)
		}

		if option.Config.NodePortAlg != option.NodePortAlgRandom &&
			option.Config.NodePortAlg != option.NodePortAlgMaglev {
			return false, fmt.Errorf("Invalid value for --%s: %s", option.NodePortAlg, option.Config.NodePortAlg)
		}

		if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled &&
			option.Config.NodePortAcceleration != option.NodePortAccelerationGeneric &&
			option.Config.NodePortAcceleration != option.NodePortAccelerationNative {
			return false, fmt.Errorf("Invalid value for --%s: %s", option.NodePortAcceleration, option.Config.NodePortAcceleration)
		}

		if option.Config.KubeProxyReplacement == option.KubeProxyReplacementProbe {
			// We let kube-proxy do the less efficient bind-protection in
			// this case to avoid the latter throwing (harmless) warnings
			// to its log that bind request is rejected.
			option.Config.NodePortBindProtection = false
		} else if !option.Config.NodePortBindProtection {
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
				return false, fmt.Errorf("Invalid value for --%s: %d, supported values are: %v",
					option.MaglevTableSize, option.Config.MaglevTableSize, supportedPrimes)
			}
			if err := maglev.Init(
				option.Config.MaglevHashSeed,
				uint64(option.Config.MaglevTableSize),
			); err != nil {
				return false, fmt.Errorf("Failed to initialize maglev hash seeds: %w", err)
			}
		}
	}

	if option.Config.EnableNodePort {
		found := false
		if h := probesManager.GetHelpers("sched_act"); h != nil {
			if _, ok := h["bpf_fib_lookup"]; ok {
				found = true
			}
		}
		if !found {
			msg := "BPF NodePort services needs kernel 4.17.0 or newer."
			if strict {
				return false, fmt.Errorf(msg)
			} else {
				disableNodePort()
				log.Warn(msg + " Disabling BPF NodePort.")
			}
		}

		if err := checkNodePortAndEphemeralPortRanges(); err != nil {
			if strict {
				return false, err
			} else {
				disableNodePort()
				log.WithError(err).Warn("Disabling BPF NodePort.")
			}
		}
	}

	if option.Config.EnableHostReachableServices {
		// Try to auto-load IPv6 module if it hasn't been done yet as there can
		// be v4-in-v6 connections even if the agent has v6 support disabled.
		probe.HaveIPv6Support()

		if option.Config.EnableMKE {
			foundClassid := false
			foundCookie := false
			if h := probesManager.GetHelpers("cgroup_sock_addr"); h != nil {
				if _, ok := h["bpf_get_cgroup_classid"]; ok {
					foundClassid = true
				}
				if _, ok := h["bpf_get_netns_cookie"]; ok {
					foundCookie = true
				}
			}
			if !foundClassid || !foundCookie {
				if strict {
					log.Fatalf("BPF kube-proxy replacement under MKE with --%s needs kernel 5.7 or newer", option.EnableMKE)
				} else {
					option.Config.EnableHostServicesTCP = false
					option.Config.EnableHostServicesUDP = false
					log.Warnf("Disabling host reachable services under MKE with --%s. Needs kernel 5.7 or newer.", option.EnableMKE)
				}
			}
		}

		option.Config.EnableHostServicesPeer = true
		if option.Config.EnableIPv4 {
			if err := bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET4_GETPEERNAME); err != nil {
				option.Config.EnableHostServicesPeer = false
			}
		}
		if option.Config.EnableIPv6 {
			if err := bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET6_GETPEERNAME); err != nil {
				option.Config.EnableHostServicesPeer = false
			}
		}
		if option.Config.EnableHostServicesTCP && option.Config.EnableIPv4 {
			err := probeCgroupSupportTCP(strict, true)
			if err != nil {
				return false, err
			}
		}
		if option.Config.EnableHostServicesTCP && option.Config.EnableIPv6 {
			err := probeCgroupSupportTCP(strict, false)
			if err != nil {
				return false, err
			}
		}
		if option.Config.EnableHostServicesUDP && option.Config.EnableIPv4 {
			err := probeCgroupSupportUDP(strict, true)
			if err != nil {
				return false, err
			}
		}
		if option.Config.EnableHostServicesUDP && option.Config.EnableIPv6 {
			err := probeCgroupSupportUDP(strict, false)
			if err != nil {
				return false, err
			}
		}
		if !option.Config.EnableHostServicesTCP && !option.Config.EnableHostServicesUDP {
			option.Config.EnableHostReachableServices = false
		}
	} else {
		option.Config.EnableHostServicesTCP = false
		option.Config.EnableHostServicesUDP = false
	}

	if option.Config.EnableSessionAffinity {
		if !probesManager.GetMapTypes().HaveLruHashMapType {
			msg := "SessionAffinity feature requires BPF LRU maps"
			if strict {
				return false, fmt.Errorf(msg)
			} else {
				log.Warnf("%s. Disabling the feature.", msg)
				option.Config.EnableSessionAffinity = false
			}

		}
	}
	if option.Config.EnableSessionAffinity && option.Config.EnableHostReachableServices {
		found1, found2 := false, false
		if h := probesManager.GetHelpers("cgroup_sock"); h != nil {
			_, found1 = h["bpf_get_netns_cookie"]
		}
		if h := probesManager.GetHelpers("cgroup_sock_addr"); h != nil {
			_, found2 = h["bpf_get_netns_cookie"]
		}
		if !(found1 && found2) {
			log.Warn("Session affinity for host reachable services needs kernel 5.7.0 or newer " +
				"to work properly when accessed from inside cluster: the same service endpoint " +
				"will be selected from all network namespaces on the host.")
		}
	}

	if option.Config.EnableNodePort {
		if option.Config.TunnelingEnabled() &&
			option.Config.NodePortMode != option.NodePortModeSNAT {

			log.Warnf("Disabling NodePort's %q mode feature due to tunneling mode being enabled",
				option.Config.NodePortMode)
			option.Config.NodePortMode = option.NodePortModeSNAT
		}

		if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled &&
			option.Config.TunnelingEnabled() {

			return false, fmt.Errorf("Cannot use NodePort acceleration with tunneling. Either run cilium-agent with --%s=%s or --%s=%s",
				option.NodePortAcceleration, option.NodePortAccelerationDisabled, option.TunnelName, option.TunnelDisabled)
		}

		if option.Config.NodePortMode == option.NodePortModeDSR &&
			option.Config.LoadBalancerDSRDispatch == option.DSRDispatchIPIP {
			if option.Config.DatapathMode != datapathOption.DatapathModeLBOnly {
				return false, fmt.Errorf("DSR dispatch mode %s only supported for --%s=%s", option.Config.LoadBalancerDSRDispatch, option.DatapathMode, datapathOption.DatapathModeLBOnly)
			}
			if option.Config.NodePortAcceleration == option.NodePortAccelerationDisabled {
				return false, fmt.Errorf("DSR dispatch mode %s currently only available under XDP acceleration", option.Config.LoadBalancerDSRDispatch)
			}
		}

		if option.Config.EnableRecorder {
			found := false
			if h := probesManager.GetHelpers("xdp"); h != nil {
				if _, ok := h["bpf_ktime_get_boot_ns"]; ok {
					found = true
				}
			}
			if !found {
				return false, fmt.Errorf("pcap recorder --%s datapath needs kernel 5.8.0 or newer", option.EnableRecorder)
			}
		}

		option.Config.EnableHealthDatapath =
			option.Config.DatapathMode == datapathOption.DatapathModeLBOnly &&
				option.Config.NodePortMode == option.NodePortModeDSR &&
				option.Config.LoadBalancerDSRDispatch == option.DSRDispatchIPIP
		if option.Config.EnableHealthDatapath {
			found := false
			if h := probesManager.GetHelpers("cgroup_sock_addr"); h != nil {
				if _, ok := h["bpf_getsockopt"]; ok {
					found = true
				}
			}
			if !found {
				option.Config.EnableHealthDatapath = false
				log.Info("BPF load-balancer health check datapath needs kernel 5.12.0 or newer. Disabling BPF load-balancer health check datapath.")
			}
		}
	}

	if option.Config.InstallNoConntrackIptRules {
		// InstallNoConntrackIptRules can only be enabled when Cilium is
		// running in full KPR mode as otherwise conntrack would be
		// required for NAT operations
		if !option.Config.KubeProxyReplacementFullyEnabled() {
			return false, fmt.Errorf("%s requires the agent to run with %s=%s.",
				option.InstallNoConntrackIptRules, option.KubeProxyReplacement, option.KubeProxyReplacementStrict)
		}

		if option.Config.MasqueradingEnabled() && !option.Config.EnableBPFMasquerade {
			return false, fmt.Errorf("%s requires the agent to run with %s.",
				option.InstallNoConntrackIptRules, option.EnableBPFMasquerade)
		}
	}

	if option.Config.BPFSocketLBHostnsOnly {
		if !option.Config.EnableHostReachableServices {
			option.Config.BPFSocketLBHostnsOnly = false
			log.Warnf("%s only takes effect when %s is true", option.BPFSocketLBHostnsOnly, option.EnableHostReachableServices)
		} else {
			found := false
			if helpers := probesManager.GetHelpers("cgroup_sock_addr"); helpers != nil {
				if _, ok := helpers["bpf_get_netns_cookie"]; ok {
					found = true
				}
			}
			if !found {
				option.Config.BPFSocketLBHostnsOnly = false
				log.Warn("Without network namespace cookie lookup functionality, BPF datapath " +
					"cannot distinguish root and non-root namespace, skipping socket-level " +
					"loadbalancing will not work. Istio routing chains will be missed. " +
					"Needs kernel version >= 5.7")
			}
		}
	}

	return strict, nil
}

func probeManagedNeighborSupport() {
	if option.Config.DryMode {
		return
	}

	probesManager := probes.NewProbeManager()
	found := false
	// Probes for kernel commit:
	//   856c02dbce4f ("bpf: Introduce helper bpf_get_branch_snapshot")
	// This is a bit of a workaround given feature probing for netlink
	// neighboring subsystem is cumbersome. The commit was added in the
	// same release as managed neighbors, that is, 5.16+.
	if h := probesManager.GetHelpers("kprobe"); h != nil {
		if _, ok := h["bpf_get_branch_snapshot"]; ok {
			found = true
		}
	}
	if found {
		log.Info("Using Managed Neighbor Kernel support")
		option.Config.ARPPingKernelManaged = true
	}
}

func probeCgroupSupportTCP(strict, ipv4 bool) error {
	var err error

	if ipv4 {
		err = bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET4_CONNECT)
	} else {
		err = bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET6_CONNECT)
	}
	if err != nil {
		msg := "BPF host reachable services for TCP needs kernel 4.17.0 or newer."
		if errors.Is(err, unix.EPERM) {
			msg = "Cilium cannot load bpf programs. Security profiles like SELinux may be restricting permissions."
		}

		if strict {
			return fmt.Errorf(msg)
		} else {
			option.Config.EnableHostServicesTCP = false
			log.WithError(err).Warn(msg + " Disabling the feature.")
		}
	}
	return nil
}

func probeCgroupSupportUDP(strict, ipv4 bool) error {
	var err error

	if ipv4 {
		err = bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_UDP4_RECVMSG)
	} else {
		err = bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_UDP6_RECVMSG)
	}
	if err != nil {
		scopedLog := log.WithError(err)
		msg := fmt.Sprintf("BPF host reachable services for UDP needs kernel 4.19.57, 5.1.16, 5.2.0 or newer. If you run an older kernel and only need TCP, then specify: --%s=tcp and --%s=%s", option.HostReachableServicesProtos, option.KubeProxyReplacement, option.KubeProxyReplacementPartial)
		if errors.Is(err, unix.EPERM) {
			msg = "Cilium cannot load bpf programs. Security profiles like SELinux may be restricting permissions."
		}

		if strict {
			return fmt.Errorf(msg)
		} else {
			option.Config.EnableHostServicesUDP = false
			scopedLog.Warn(msg + " Disabling the feature.")
		}
	}
	return nil
}

// finishKubeProxyReplacementInit finishes initialization of kube-proxy
// replacement after all devices are known.
func finishKubeProxyReplacementInit(isKubeProxyReplacementStrict bool) error {
	if option.Config.EnableNodePort {
		if err := node.InitNodePortAddrs(option.Config.Devices, option.Config.LBDevInheritIPAddr); err != nil {
			msg := "Failed to initialize NodePort addrs."
			if isKubeProxyReplacementStrict {
				return fmt.Errorf(msg)
			} else {
				disableNodePort()
				log.WithError(err).Warn(msg + " Disabling BPF NodePort.")
			}
		}
	}

	if !option.Config.EnableNodePort {
		// Make sure that NodePort dependencies are disabled
		disableNodePort()
		return nil
	}

	if option.Config.EnableSVCSourceRangeCheck && !probe.HaveFullLPM() {
		msg := fmt.Sprintf("--%s requires kernel 4.16 or newer.",
			option.EnableSVCSourceRangeCheck)
		if isKubeProxyReplacementStrict {
			return fmt.Errorf(msg)
		} else {
			log.Warnf(msg + " Disabling the check.")
			option.Config.EnableSVCSourceRangeCheck = false
		}
	}

	// +-------------------------------------------------------+
	// | After this point, BPF NodePort should not be disabled |
	// +-------------------------------------------------------+

	// For MKE, we only need to change/extend the socket LB behavior in case
	// of kube-proxy replacement. Otherwise, nothing else is needed.
	if option.Config.EnableMKE && option.Config.EnableHostReachableServices {
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
		// All cases below still need to be implemented ...
		case option.Config.EnableEndpointRoutes:
			msg = fmt.Sprintf("BPF host routing is currently not supported with %s.", option.EnableEndpointRoutes)
		case !mac.HaveMACAddrs(option.Config.Devices):
			msg = "BPF host routing is currently not supported with devices without L2 addr."
		case option.Config.EnableWireguard:
			msg = fmt.Sprintf("BPF host routing is currently not compatible with Wireguard (--%s).", option.EnableWireguard)
		default:
			probesManager := probes.NewProbeManager()
			foundNeigh := false
			foundPeer := false
			if h := probesManager.GetHelpers("sched_cls"); h != nil {
				_, foundNeigh = h["bpf_redirect_neigh"]
				_, foundPeer = h["bpf_redirect_peer"]
			}
			if !foundNeigh || !foundPeer {
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

	for _, iface := range option.Config.Devices {
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
		len(option.Config.Devices) > 1 {

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
			valBytes, err := io.ReadAll(f)
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

func hasFullHostReachableServices() bool {
	return option.Config.EnableHostReachableServices &&
		option.Config.EnableHostServicesTCP &&
		option.Config.EnableHostServicesUDP
}
