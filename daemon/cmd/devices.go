// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2021 Authors of Cilium

// This module implements Cilium's network device detection.

package cmd

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	excludedDevicePrefixes = []string{
		"cilium_",
		"lo",
		"lxc",
		"cni",
		"docker",
	}

	// Route filter to look at all routing tables.
	routeFilter = netlink.Route{
		Table: unix.RT_TABLE_UNSPEC,
	}
	routeFilterMask = netlink.RT_FILTER_TABLE
)

type DeviceManager struct {
	lock.Mutex
	devices map[string]struct{}
}

func NewDeviceManager() *DeviceManager {
	return &DeviceManager{
		devices: make(map[string]struct{}),
	}
}

// Detect tries to detect devices to which BPF programs may be loaded.
// See areDevicesRequired() for features that require the device information.
//
// The devices are detected by looking at all the configured global unicast
// routes in the system.
func (dm *DeviceManager) Detect() error {
	dm.Lock()
	defer dm.Unlock()
	dm.devices = make(map[string]struct{})

	if err := expandDevices(); err != nil {
		return err
	}

	l3DevOK := true
	if !option.Config.EnableHostLegacyRouting {
		// Probe whether fast redirect is supported for L3 devices. This will
		// invoke bpftool and requires root privileges, so we're only probing
		// when necessary.
		l3DevOK = supportL3Dev()
	}

	if len(option.Config.Devices) == 0 && areDevicesRequired() {
		// Detect the devices from the system routing table by finding the devices
		// which have global unicast routes.
		family := netlink.FAMILY_ALL
		if option.Config.EnableIPv4 && !option.Config.EnableIPv6 {
			family = netlink.FAMILY_V4
		} else if !option.Config.EnableIPv4 && option.Config.EnableIPv6 {
			family = netlink.FAMILY_V6
		}

		routes, err := netlink.RouteListFiltered(family, &routeFilter, routeFilterMask)
		if err != nil {
			return fmt.Errorf("cannot retrieve routes for device detection: %w", err)
		}
		dm.updateDevicesFromRoutes(l3DevOK, routes)
	} else {
		for _, dev := range option.Config.Devices {
			dm.devices[dev] = struct{}{}
		}
	}

	detectDirectRoutingDev := option.Config.EnableNodePort
	if option.Config.DirectRoutingDevice != "" {
		dm.devices[option.Config.DirectRoutingDevice] = struct{}{}
		detectDirectRoutingDev = false
	}

	detectIPv6MCastDev := option.Config.EnableIPv6NDP
	if option.Config.IPv6MCastDevice != "" {
		dm.devices[option.Config.IPv6MCastDevice] = struct{}{}
		detectIPv6MCastDev = false
	}

	if detectDirectRoutingDev || detectIPv6MCastDev {
		k8sNodeDev := ""
		k8sNodeLink, err := findK8SNodeIPLink()
		if err == nil {
			k8sNodeDev = k8sNodeLink.Attrs().Name
			dm.devices[k8sNodeDev] = struct{}{}
		} else if k8s.IsEnabled() {
			return fmt.Errorf("k8s is enabled, but still failed to find node IP: %w", err)
		}

		if detectDirectRoutingDev {
			// If only one device found, use that one. Otherwise use the device with k8s node IP.
			if len(dm.devices) == 1 {
				for dev := range dm.devices {
					option.Config.DirectRoutingDevice = dev
					break
				}
			} else if k8sNodeDev != "" {
				option.Config.DirectRoutingDevice = k8sNodeDev
			} else {
				return fmt.Errorf("Unable to determine direct routing device. Use --%s to specify it",
					option.DirectRoutingDevice)
			}
			log.WithField(option.DirectRoutingDevice, option.Config.DirectRoutingDevice).
				Info("Direct routing device detected")
		}

		if detectIPv6MCastDev {
			if k8sNodeLink != nil && k8sNodeLink.Attrs().Flags&net.FlagMulticast != 0 {
				option.Config.IPv6MCastDevice = k8sNodeDev
				log.WithField(option.IPv6MCastDevice, option.Config.IPv6MCastDevice).Info("IPv6 multicast device detected")
			} else {
				return fmt.Errorf("Unable to determine Multicast device. Use --%s to specify it",
					option.IPv6MCastDevice)
			}
		}
	}

	option.Config.Devices = dm.getDevices()
	log.WithField(logfields.Devices, option.Config.Devices).Info("Detected devices")

	return nil
}

// GetDevices returns the current list of devices Cilium should attach programs to.
func (dm *DeviceManager) GetDevices() []string {
	dm.Lock()
	defer dm.Unlock()
	return dm.getDevices()
}

func (dm *DeviceManager) getDevices() []string {
	devs := make([]string, 0, len(dm.devices))
	for dev := range dm.devices {
		devs = append(devs, dev)
	}
	sort.Strings(devs)
	return devs
}

// Exclude devices that have one or more of these flags set.
var excludedIfFlagsMask uint32 = unix.IFF_SLAVE | unix.IFF_LOOPBACK

// isViableDevice returns true if the given link is usable and Cilium should attach
// programs to it.
func (dm *DeviceManager) isViableDevice(l3DevOK, hasDefaultRoute bool, link netlink.Link) bool {
	name := link.Attrs().Name

	// Do not consider any of the excluded devices.
	for _, p := range excludedDevicePrefixes {
		if strings.HasPrefix(name, p) {
			log.WithField(logfields.Device, name).
				Debugf("Skipping device as it has excluded prefix '%s'", p)
			return false
		}
	}

	// Skip devices that have an excluded interface flag set.
	if link.Attrs().RawFlags&excludedIfFlagsMask != 0 {
		log.WithField(logfields.Device, name).Debugf("Skipping device as it has excluded flag (%x)", link.Attrs().RawFlags)
		return false
	}

	// Ignore L3 devices if we cannot support them.
	if !l3DevOK && !mac.LinkHasMacAddr(link) {
		log.WithField(logfields.Device, name).
			Info("Ignoring L3 device; >= 5.8 kernel is required.")
		return false
	}

	switch link.Type() {
	case "veth":
		// Skip veth devices that don't have a default route.
		// This is a workaround for kubernetes-in-docker. We want to avoid
		// veth devices in general as they may be leftovers from another CNI.
		if !hasDefaultRoute {
			log.WithField(logfields.Device, name).
				Debug("Ignoring veth device as it has no default route")
			return false
		}

	case "bridge", "openvswitch":
		// Skip bridge devices as they're very unlikely to be used for K8s
		// purposes. In the rare cases where a user wants to load datapath
		// programs onto them they can override device detection with --devices.
		log.WithField(logfields.Device, name).Debug("Ignoring bridge-like device")
		return false

	}

	if link.Attrs().MasterIndex > 0 {
		if master, err := netlink.LinkByIndex(link.Attrs().MasterIndex); err == nil {
			switch master.Type() {
			case "bridge", "openvswitch":
				log.WithField(logfields.Device, name).Debug("Ignoring device attached to bridge")
				return false

			case "bond", "team":
				log.WithField(logfields.Device, name).Debug("Ignoring bonded device")
				return false
			}

		}
	}

	return true
}

type linkInfo struct {
	hasDefaultRoute bool
}

// updateDevicesFromRoutes processes a batch of routes and updates the set of
// devices. Returns true if devices changed.
func (dm *DeviceManager) updateDevicesFromRoutes(l3DevOK bool, routes []netlink.Route) bool {
	linkInfos := make(map[int]linkInfo)

	// Collect all link indices mentioned in the route update batch
	for _, route := range routes {
		// Only consider devices that have global unicast routes,
		// e.g. skip loopback, multicast and link local routes.
		if route.Dst != nil && !route.Dst.IP.IsGlobalUnicast() {
			continue
		}
		if route.Table == unix.RT_TABLE_LOCAL {
			continue
		}
		linkInfo := linkInfos[route.LinkIndex]
		linkInfo.hasDefaultRoute = linkInfo.hasDefaultRoute || route.Dst == nil
		linkInfos[route.LinkIndex] = linkInfo
	}

	changed := false
	for index, info := range linkInfos {
		link, err := netlink.LinkByIndex(index)
		if err != nil {
			log.WithError(err).WithField(logfields.LinkIndex, index).
				Warn("Failed to get link by index")
			continue
		}
		name := link.Attrs().Name

		// Skip devices we already know.
		if _, exists := dm.devices[name]; exists {
			continue
		}

		viable := dm.isViableDevice(l3DevOK, info.hasDefaultRoute, link)
		if viable {
			dm.devices[name] = struct{}{}
			changed = true
		}
	}
	return changed
}

// expandDevices expands all wildcard device names to concrete devices.
// e.g. device "eth+" expands to "eth0,eth1" etc. Non-matching wildcards are ignored.
func expandDevices() error {
	allLinks, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("Device wildcard expansion failed to fetch devices: %w", err)
	}
	expandedDevices := make(map[string]struct{})
	for _, iface := range option.Config.Devices {
		if strings.HasSuffix(iface, "+") {
			prefix := strings.TrimRight(iface, "+")
			for _, link := range allLinks {
				attrs := link.Attrs()
				if strings.HasPrefix(attrs.Name, prefix) {
					expandedDevices[attrs.Name] = struct{}{}
				}
			}
		} else {
			expandedDevices[iface] = struct{}{}
		}
	}
	if len(option.Config.Devices) > 0 && len(expandedDevices) == 0 {
		// User defined devices, but expansion yielded no devices. Fail here to not
		// surprise with auto-detection.
		return fmt.Errorf("Device wildcard expansion failed to detect devices. Please verify --%s option.",
			option.Devices)
	}

	option.Config.Devices = make([]string, 0, len(expandedDevices))
	for dev := range expandedDevices {
		option.Config.Devices = append(option.Config.Devices, dev)
	}
	sort.Strings(option.Config.Devices)
	return nil
}

func areDevicesRequired() bool {
	return option.Config.EnableNodePort ||
		option.Config.EnableHostFirewall ||
		option.Config.EnableBandwidthManager
}

func findK8SNodeIPLink() (netlink.Link, error) {
	nodeIP := node.GetK8sNodeIP()

	if nodeIP == nil {
		return nil, fmt.Errorf("Failed to find K8s node device as node IP is not known")
	}

	var family int
	if nodeIP.To4() != nil {
		family = netlink.FAMILY_V4
	} else {
		family = netlink.FAMILY_V6
	}

	if addrs, err := netlink.AddrList(nil, family); err == nil {
		for _, a := range addrs {
			if a.IP.Equal(nodeIP) {
				link, err := netlink.LinkByIndex(a.LinkIndex)
				if err != nil {
					return nil, err
				}
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("K8s node device not found")
}

// supportL3Dev returns true if the kernel is new enough to support fast redirection of
// packets coming from L3 devices using bpf_skb_redirect_peer.
func supportL3Dev() bool {
	probesManager := probes.NewProbeManager()
	if h := probesManager.GetHelpers("sched_cls"); h != nil {
		_, found := h["bpf_skb_change_head"]
		return found
	}
	return false
}
