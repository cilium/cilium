// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This module implements Cilium's network device detection.

package linux

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
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
	filter  deviceFilter
	handle  *netlink.Handle
	netns   netns.NsHandle
}

func NewDeviceManager() (*DeviceManager, error) {
	return NewDeviceManagerAt(netns.None())
}

func NewDeviceManagerAt(netns netns.NsHandle) (*DeviceManager, error) {
	handle, err := netlink.NewHandleAt(netns)
	if err != nil {
		return nil, fmt.Errorf("unable to setup device manager: %w", err)
	}
	return &DeviceManager{
		devices: make(map[string]struct{}),
		filter:  deviceFilter(option.Config.GetDevices()),
		handle:  handle,
		netns:   netns,
	}, nil
}

// Detect tries to detect devices to which BPF programs may be loaded.
// See AreDevicesRequired() for features that require the device information.
//
// The devices are detected by looking at all the configured global unicast
// routes in the system.
func (dm *DeviceManager) Detect(k8sEnabled bool) ([]string, error) {
	dm.Lock()
	defer dm.Unlock()
	dm.devices = make(map[string]struct{})

	if err := dm.expandDevices(); err != nil {
		return nil, err
	}

	if err := dm.expandDirectRoutingDevice(); err != nil {
		return nil, err
	}

	l3DevOK := true
	if !option.Config.EnableHostLegacyRouting && !option.Config.DryMode {
		// Probe whether BPF host routing is supported for L3 devices. This will
		// invoke bpftool and requires root privileges, so we're only probing
		// when necessary.
		l3DevOK = supportL3Dev()
	}

	if len(option.Config.GetDevices()) == 0 && option.Config.AreDevicesRequired() {
		// Detect the devices from the system routing table by finding the devices
		// which have global unicast routes.
		family := netlink.FAMILY_ALL
		if option.Config.EnableIPv4 && !option.Config.EnableIPv6 {
			family = netlink.FAMILY_V4
		} else if !option.Config.EnableIPv4 && option.Config.EnableIPv6 {
			family = netlink.FAMILY_V6
		}

		routes, err := dm.handle.RouteListFiltered(family, &routeFilter, routeFilterMask)
		if err != nil {
			return nil, fmt.Errorf("cannot retrieve routes for device detection: %w", err)
		}
		dm.updateDevicesFromRoutes(l3DevOK, routes)
	} else {
		for _, dev := range option.Config.GetDevices() {
			dm.devices[dev] = struct{}{}
		}
	}

	detectDirectRoutingDev := option.Config.DirectRoutingDeviceRequired()
	if option.Config.DirectRoutingDeviceRequired() && option.Config.DirectRoutingDevice != "" {
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
		} else if k8sEnabled {
			return nil, fmt.Errorf("k8s is enabled, but still failed to find node IP: %w", err)
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
				return nil, fmt.Errorf("unable to determine direct routing device. Use --%s to specify it",
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
				return nil, fmt.Errorf("unable to determine Multicast device. Use --%s to specify it",
					option.IPv6MCastDevice)
			}
		}
	}

	deviceList := dm.getDeviceList()
	option.Config.SetDevices(deviceList)
	log.WithField(logfields.Devices, deviceList).Info("Detected devices")
	return deviceList, nil
}

func (dm *DeviceManager) getDeviceList() []string {
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

	// If user specified devices or wildcards, then skip the device if it doesn't match.
	if !dm.filter.match(name) {
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
		if master, err := dm.handle.LinkByIndex(link.Attrs().MasterIndex); err == nil {
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
		link, err := dm.handle.LinkByIndex(index)
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
		} else {
			log.WithField(logfields.Device, name).Debug("Skipping unviable device")
		}
	}
	return changed
}

// Listen starts listening to changes to network devices. When devices change the new set
// of devices is sent on the returned channel.
func (dm *DeviceManager) Listen(ctx context.Context) (chan []string, error) {
	l3DevOK := supportL3Dev()
	routeChan := make(chan netlink.RouteUpdate)
	closeChan := make(chan struct{})

	err := netlink.RouteSubscribeWithOptions(routeChan, closeChan,
		netlink.RouteSubscribeOptions{
			// List existing routes to make sure we did not miss changes that happened after Detect().
			ListExisting: true,
			Namespace:    &dm.netns,
		})
	if err != nil {
		return nil, err
	}

	linkChan := make(chan netlink.LinkUpdate)

	err = netlink.LinkSubscribeWithOptions(linkChan, closeChan, netlink.LinkSubscribeOptions{
		ListExisting: false,
		Namespace:    &dm.netns,
	})
	if err != nil {
		return nil, err
	}

	devicesChan := make(chan []string, 1)

	// Find links deleted after Detect()
	if allLinks, err := dm.handle.LinkList(); err == nil {
		changed := false
		linksByName := map[string]struct{}{}
		for _, link := range allLinks {
			linksByName[link.Attrs().Name] = struct{}{}
		}
		dm.Lock()
		for name := range dm.devices {
			if _, exists := linksByName[name]; !exists {
				delete(dm.devices, name)
				changed = true
			}
		}
		devices := dm.getDeviceList()
		dm.Unlock()

		if changed {
			log.WithField(logfields.Devices, devices).Info("Devices changed")
			devicesChan <- devices
		}
	}

	go func() {
		log.Info("Listening for device changes")

		for {
			devicesChanged := false
			var devices []string

			select {
			case <-ctx.Done():
				log.Debug("context closed, Listen() stopping")
				close(closeChan)
				close(devicesChan)
				// drain the route and link channels
				for range routeChan {
				}
				for range linkChan {
				}
				return

			case update := <-routeChan:
				if update.Type == unix.RTM_NEWROUTE {
					dm.Lock()
					devicesChanged = dm.updateDevicesFromRoutes(l3DevOK, []netlink.Route{update.Route})
					devices = dm.getDeviceList()
					dm.Unlock()
				}

			case update := <-linkChan:
				if update.Header.Type == unix.RTM_DELLINK {
					name := update.Attrs().Name
					dm.Lock()
					if _, ok := dm.devices[name]; ok {
						delete(dm.devices, name)
						devicesChanged = true
					}
					devices = dm.getDeviceList()
					dm.Unlock()
				}
			}

			if devicesChanged {
				log.WithField(logfields.Devices, devices).Info("Devices changed")
				devicesChan <- devices
			}
		}
	}()
	return devicesChan, nil
}

// expandDevices expands all wildcard device names to concrete devices.
// e.g. device "eth+" expands to "eth0,eth1" etc. Non-matching wildcards are ignored.
func (dm *DeviceManager) expandDevices() error {
	expandedDevices, err := dm.expandDeviceWildcards(option.Config.GetDevices(), option.Devices)
	if err != nil {
		return err
	}
	option.Config.SetDevices(expandedDevices)
	return nil
}

// expandDirectRoutingDevice expands all wildcard device names to concrete devices and picks a first one.
func (dm *DeviceManager) expandDirectRoutingDevice() error {
	if option.Config.DirectRoutingDevice == "" {
		return nil
	}
	expandedDevices, err := dm.expandDeviceWildcards([]string{option.Config.DirectRoutingDevice}, option.DirectRoutingDevice)
	if err != nil {
		return err
	}
	option.Config.DirectRoutingDevice = expandedDevices[0]
	return nil
}

func (dm *DeviceManager) expandDeviceWildcards(devices []string, option string) ([]string, error) {
	allLinks, err := dm.handle.LinkList()
	if err != nil {
		return nil, fmt.Errorf("device wildcard expansion failed to fetch devices: %w", err)
	}
	expandedDevicesMap := make(map[string]struct{})
	for _, iface := range devices {
		if strings.HasSuffix(iface, "+") {
			prefix := strings.TrimRight(iface, "+")
			for _, link := range allLinks {
				attrs := link.Attrs()
				if strings.HasPrefix(attrs.Name, prefix) {
					expandedDevicesMap[attrs.Name] = struct{}{}
				}
			}
		} else {
			expandedDevicesMap[iface] = struct{}{}
		}
	}
	if len(devices) > 0 && len(expandedDevicesMap) == 0 {
		// User defined devices, but expansion yielded no devices. Fail here to not
		// surprise with auto-detection.
		return nil, fmt.Errorf("device wildcard expansion failed to detect devices. Please verify --%s option.",
			option)
	}

	expandedDevices := make([]string, 0, len(expandedDevicesMap))
	for dev := range expandedDevicesMap {
		expandedDevices = append(expandedDevices, dev)
	}
	sort.Strings(expandedDevices)
	return expandedDevices, nil
}

func findK8SNodeIPLink() (netlink.Link, error) {
	nodeIP := node.GetK8sNodeIP()

	if nodeIP == nil {
		return nil, fmt.Errorf("failed to find K8s node device as node IP is not known")
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

				// When IPv6 is enabled and the node has an IPv6 address, the 'cilium_host'
				// interface is assigned the same IP of the node itself. Let's skip it here.
				if link.Attrs().Name == defaults.HostDevice {
					continue
				}

				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("K8s node device not found")
}

// supportL3Dev returns true if the kernel is new enough to support BPF host routing of
// packets coming from L3 devices using bpf_skb_redirect_peer.
func supportL3Dev() bool {
	return probes.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbChangeHead) == nil
}

type deviceFilter []string

func (lst deviceFilter) match(dev string) bool {
	if len(lst) == 0 {
		return true
	}
	for _, entry := range lst {
		if strings.HasSuffix(entry, "+") {
			prefix := strings.TrimRight(entry, "+")
			return strings.HasPrefix(dev, prefix)
		} else if dev == entry {
			return true
		}
	}
	return false
}
