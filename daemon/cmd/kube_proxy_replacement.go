// Copyright 2019-2020 Authors of Cilium
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

// This module contains the kube-proxy replacement initialization helpers.

package cmd

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/probe"
	"github.com/cilium/cilium/pkg/sysctl"

	"github.com/vishvananda/netlink"
)

func initKubeProxyReplacementOptions() (strict bool) {
	if option.Config.KubeProxyReplacement != option.KubeProxyReplacementStrict &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementPartial &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementProbe &&
		option.Config.KubeProxyReplacement != option.KubeProxyReplacementDisabled {
		log.Fatalf("Invalid value for --%s: %s", option.KubeProxyReplacement, option.Config.KubeProxyReplacement)
	}

	if option.Config.DisableK8sServices {
		if option.Config.KubeProxyReplacement != option.KubeProxyReplacementDisabled {
			log.Warnf("Service handling disabled. Auto-disabling --%s from \"%s\" to \"%s\"",
				option.KubeProxyReplacement, option.Config.KubeProxyReplacement,
				option.KubeProxyReplacementDisabled)
			option.Config.KubeProxyReplacement = option.KubeProxyReplacementDisabled
		}
	}

	if option.Config.KubeProxyReplacement == option.KubeProxyReplacementDisabled {
		log.Infof("Auto-disabling %q, %q, %q, %q, %q features",
			option.EnableNodePort, option.EnableExternalIPs,
			option.EnableHostReachableServices, option.EnableHostPort,
			option.EnableSessionAffinity)

		disableNodePort()
		option.Config.EnableHostReachableServices = false
		option.Config.EnableHostServicesTCP = false
		option.Config.EnableHostServicesUDP = false
		option.Config.EnableSessionAffinity = false

		return
	}

	probesManager := probes.NewProbeManager()

	// strict denotes to panic if any to-be enabled feature cannot be enabled
	strict = option.Config.KubeProxyReplacement != option.KubeProxyReplacementProbe

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
		option.Config.DisableK8sServices = false
	}

	if option.Config.EnableNodePort {
		if option.Config.EnableIPSec {
			msg := "IPSec cannot be used with BPF NodePort."
			if strict {
				log.Fatal(msg)
			} else {
				disableNodePort()
				log.Warn(msg + " Disabling BPF NodePort feature.")
			}
		}

		if option.Config.NodePortMode != option.NodePortModeSNAT &&
			option.Config.NodePortMode != option.NodePortModeDSR &&
			option.Config.NodePortMode != option.NodePortModeHybrid {
			log.Fatalf("Invalid value for --%s: %s", option.NodePortMode, option.Config.NodePortMode)
		}

		if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled &&
			option.Config.NodePortAcceleration != option.NodePortAccelerationGeneric &&
			option.Config.NodePortAcceleration != option.NodePortAccelerationNative {
			log.Fatalf("Invalid value for --%s: %s", option.NodePortAcceleration, option.Config.NodePortAcceleration)
		}

		if !option.Config.NodePortBindProtection {
			log.Warning("NodePort BPF configured without bind(2) protection against service ports")
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
				log.Fatal(msg)
			} else {
				disableNodePort()
				log.Warn(msg + " Disabling BPF NodePort.")
			}
		}

		if err := checkNodePortAndEphemeralPortRanges(); err != nil {
			if strict {
				log.Fatal(err)
			} else {
				disableNodePort()
				log.Warn(fmt.Sprintf("%s. Disabling BPF NodePort.", err))
			}
		}
	}

	if option.Config.EnableHostReachableServices {
		// Try to auto-load IPv6 module if it hasn't been done yet as there can
		// be v4-in-v6 connections even if the agent has v6 support disabled.
		probe.HaveIPv6Support()

		option.Config.EnableHostServicesPeer = true
		if option.Config.EnableIPv4 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET4_GETPEERNAME) != nil ||
			option.Config.EnableIPv6 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET6_GETPEERNAME) != nil {
			option.Config.EnableHostServicesPeer = false
		}

		if option.Config.EnableHostServicesTCP &&
			(option.Config.EnableIPv4 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET4_CONNECT) != nil ||
				option.Config.EnableIPv6 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_INET6_CONNECT) != nil) {
			msg := "BPF host reachable services for TCP needs kernel 4.17.0 or newer."
			if strict {
				log.Fatal(msg)
			} else {
				option.Config.EnableHostServicesTCP = false
				log.Warn(msg + " Disabling the feature.")
			}
		}
		if option.Config.EnableHostServicesUDP &&
			(option.Config.EnableIPv4 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_UDP4_RECVMSG) != nil ||
				option.Config.EnableIPv6 && bpf.TestDummyProg(bpf.ProgTypeCgroupSockAddr, bpf.BPF_CGROUP_UDP6_RECVMSG) != nil) {
			msg := fmt.Sprintf("BPF host reachable services for UDP needs kernel 4.19.57, 5.1.16, 5.2.0 or newer. If you run an older kernel and only need TCP, then specify: --%s=tcp and --%s=%s", option.HostReachableServicesProtos, option.KubeProxyReplacement, option.KubeProxyReplacementPartial)
			if strict {
				log.Fatal(msg)
			} else {
				option.Config.EnableHostServicesUDP = false
				log.Warn(msg + " Disabling the feature.")
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
				log.Fatal(msg)
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
		if option.Config.Tunnel != option.TunnelDisabled &&
			option.Config.NodePortMode != option.NodePortModeSNAT {

			log.Warnf("Disabling NodePort's %q mode feature due to tunneling mode being enabled",
				option.Config.NodePortMode)
			option.Config.NodePortMode = option.NodePortModeSNAT
		}

		if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled {
			if option.Config.Tunnel != option.TunnelDisabled {
				log.Fatalf("Cannot use NodePort acceleration with tunneling. Either run cilium-agent with --%s=%s or --%s=%s",
					option.NodePortAcceleration, option.NodePortAccelerationDisabled, option.TunnelName, option.TunnelDisabled)
			}
		}
	}

	return
}

// detectDevicesForNodePortAndHostFirewall tries to detect bpf_host devices
// (if needed).
func detectDevicesForNodePortAndHostFirewall(strict bool) {
	detectNodePortDevs := len(option.Config.Devices) == 0 &&
		(option.Config.EnableNodePort || option.Config.EnableHostFirewall)
	detectDirectRoutingDev := option.Config.EnableNodePort &&
		option.Config.DirectRoutingDevice == ""
	if detectNodePortDevs || detectDirectRoutingDev {
		if err := detectDevices(detectNodePortDevs, detectDirectRoutingDev); err != nil {
			msg := "Unable to detect devices for BPF NodePort."
			if strict {
				log.WithError(err).Fatal(msg)
			} else {
				disableNodePort()
				log.WithError(err).Warn(msg + " Disabling BPF NodePort.")
			}
		} else {
			l := log
			if detectNodePortDevs {
				l = l.WithField(logfields.Devices, option.Config.Devices)
			}
			if detectDirectRoutingDev {
				l = l.WithField(logfields.DirectRoutingDevice, option.Config.DirectRoutingDevice)
			}
			l.Info("Using auto-derived devices for BPF node port")
		}
	}
}

// finishKubeProxyReplacementInit finishes initialization of kube-proxy
// replacement after all devices are known.
func finishKubeProxyReplacementInit(isKubeProxyReplacementStrict bool) {
	if option.Config.EnableNodePort {
		if err := node.InitNodePortAddrs(option.Config.Devices); err != nil {
			msg := "Failed to initialize NodePort addrs."
			if isKubeProxyReplacementStrict {
				log.WithError(err).Fatal(msg)
			} else {
				disableNodePort()
				log.WithError(err).Warn(msg + " Disabling BPF NodePort.")
			}
		}
	}

	if !option.Config.EnableNodePort {
		// Make sure that NodePort dependencies are disabled
		disableNodePort()
		return
	}

	// After this point, BPF NodePort should not be disabled

	if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled {
		if option.Config.XDPDevice != "undefined" &&
			(option.Config.DirectRoutingDevice == "" ||
				option.Config.XDPDevice != option.Config.DirectRoutingDevice) {
			log.Fatalf("Cannot set NodePort acceleration device: mismatch between Prefilter device %s and NodePort device %s",
				option.Config.XDPDevice, option.Config.DirectRoutingDevice)
		}
		option.Config.XDPDevice = option.Config.DirectRoutingDevice
		if err := loader.SetXDPMode(option.Config.NodePortAcceleration); err != nil {
			log.WithError(err).Fatal("Cannot set NodePort acceleration")
		}
	}

	for _, iface := range option.Config.Devices {
		link, err := netlink.LinkByName(iface)
		if err != nil {
			log.WithError(err).Fatalf("Cannot retrieve %s link", iface)
		}
		if strings.ContainsAny(iface, "=;") {
			// Because we pass IPV{4,6}_NODEPORT addresses to bpf/init.sh
			// in a form "$IFACE_NAME1=$IPV{4,6}_ADDR1;$IFACE_NAME2=...",
			// we need to restrict the iface names. Otherwise, bpf/init.sh
			// won't properly parse the mappings.
			log.Fatalf("%s link name contains '=' or ';' character which is not allowed",
				iface)
		}
		if idx := link.Attrs().Index; idx > math.MaxUint16 {
			log.Fatalf("%s link ifindex %d exceeds max(uint16)", iface, idx)
		}
	}

	if option.Config.EnableIPv4 &&
		option.Config.Tunnel == option.TunnelDisabled &&
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

	option.Config.NodePortHairpin = len(option.Config.Devices) == 1
	if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled &&
		len(option.Config.Devices) != 1 {
		log.Fatalf("Cannot set NodePort acceleration due to multi-device setup (%q). Specify --%s with a single device to enable NodePort acceleration.", option.Config.Devices, option.Devices)
	}
}

// disableNodePort disables BPF NodePort and friends who are dependent from
// the latter.
func disableNodePort() {
	option.Config.EnableNodePort = false
	option.Config.EnableHostPort = false
	option.Config.EnableExternalIPs = false
}

func hasHardwareAddress(ifIndex int) bool {
	iface, err := netlink.LinkByIndex(ifIndex)
	if err != nil {
		return false
	}
	return len(iface.Attrs().HardwareAddr) > 0
}

// detectDevices tries to detect device names which are going to be used for
// (a) NodePort BPF, (b) direct routing in NodePort BPF.
//
// (a) is determined from a default route and the k8s node IP addr.
// (b) is derived either from NodePort BPF devices (if only one is set) or
//     from the k8s node IP addr.
func detectDevices(detectNodePortDevs, detectDirectRoutingDev bool) error {
	var err error
	devSet := map[string]struct{}{} // iface name
	ifidxByAddr := map[string]int{} // str(ip addr) => ifindex

	if addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL); err != nil {
		// Do not return error, as a device with a default route can be used
		// later as a last resort
		log.WithError(err).Warn(
			"Cannot retrieve host IP addrs for BPF NodePort device detection")
	} else {
		for _, a := range addrs {
			if hasHardwareAddress(a.LinkIndex) {
				ifidxByAddr[a.IP.String()] = a.LinkIndex
			}
		}
	}

	if detectNodePortDevs {
		if devSet, err = detectNodePortDevices(ifidxByAddr); err != nil {
			return fmt.Errorf("Unable to determine BPF NodePort devices: %s. Use --%s to specify them",
				err, option.Devices)
		}
	} else {
		for _, dev := range option.Config.Devices {
			devSet[dev] = struct{}{}
		}
	}

	if detectDirectRoutingDev {
		// If only single device was previously found, use it for direct routing.
		// Otherwise, use k8s Node IP addr to determine the device.
		if len(devSet) == 1 {
			for dev := range devSet {
				option.Config.DirectRoutingDevice = dev
			}
		} else {
			if option.Config.DirectRoutingDevice, err = detectNodeDevice(ifidxByAddr); err != nil {
				return fmt.Errorf("Unable to determine BPF NodePort direct routing device: %s. "+
					"Use --%s to specify it", err, option.DirectRoutingDevice)
			}
		}
	}
	if option.Config.DirectRoutingDevice != "" {
		devSet[option.Config.DirectRoutingDevice] = struct{}{}
	}

	option.Config.Devices = make([]string, 0, len(devSet))
	for dev := range devSet {
		option.Config.Devices = append(option.Config.Devices, dev)
	}
	return nil
}

func detectNodePortDevices(ifidxByAddr map[string]int) (map[string]struct{}, error) {
	devSet := map[string]struct{}{}

	// Find a device with a default route (for backward compatibility)
	defaultRouteDevice, err := linuxdatapath.NodeDeviceNameWithDefaultRoute()
	if err == nil {
		devSet[defaultRouteDevice] = struct{}{}
	}

	// Derive a device from k8s Node IP
	if dev, err := detectNodeDevice(ifidxByAddr); err != nil {
		log.WithError(err).Warn(
			"Cannot determine a device from k8s Node IP addr for BPF NodePort device detection")
	} else {
		devSet[dev] = struct{}{}
	}

	if len(devSet) == 0 {
		return nil, fmt.Errorf("Cannot determine any device for BPF NodePort")
	}

	return devSet, nil
}

func detectNodeDevice(ifidxByAddr map[string]int) (string, error) {
	nodeIP := node.GetK8sNodeIP()
	if nodeIP == nil {
		return "", fmt.Errorf("K8s Node IP is not set")
	}

	ifindex, found := ifidxByAddr[nodeIP.String()]
	if !found {
		return "", fmt.Errorf("Cannot find device with %s addr", nodeIP)
	}

	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return "", fmt.Errorf("Cannot find device with %s addr by %d ifindex",
			nodeIP, ifindex)
	}

	return link.Attrs().Name, nil
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
		return fmt.Errorf("Unable to read net.ipv4.ip_local_port_range")
	}
	ephemeralPortRange := strings.Split(ephemeralPortRangeStr, "\t")
	if len(ephemeralPortRange) != 2 {
		return fmt.Errorf("Invalid ephemeral port range: %s", ephemeralPortRangeStr)
	}
	ephemeralPortMin, err := strconv.Atoi(ephemeralPortRange[0])
	if err != nil {
		return fmt.Errorf("Unable to parse min port value %s for ephemeral range", ephemeralPortRange[0])
	}
	ephemeralPortMax, err := strconv.Atoi(ephemeralPortRange[1])
	if err != nil {
		return fmt.Errorf("Unable to parse max port value %s for ephemeral range", ephemeralPortRange[1])
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
		return fmt.Errorf("Unable to read net.ipv4.ip_local_reserved_ports")
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
			return fmt.Errorf("Unable to parse reserved port %q", ports[0])
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
		return fmt.Errorf("Unable to addend nodeport range (%s) to net.ipv4.ip_local_reserved_ports: %s",
			nodePortRangeStr, err)
	}

	return nil
}
