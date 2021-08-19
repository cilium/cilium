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

// This module implements device detection.

package cmd

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
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

	defaultRouteHandlingInterval = time.Millisecond * 100
)

type DeviceManager struct {
	// mu protects the closeChan.
	mu        lock.Mutex
	closeChan chan struct{}

	l3DevOK               bool
	routeHandlingInterval time.Duration
}

func NewDeviceManager() *DeviceManager {
	dm := &DeviceManager{
		l3DevOK:               supportL3Dev(),
		routeHandlingInterval: defaultRouteHandlingInterval,
		closeChan:             make(chan struct{}),
	}
	return dm
}

// isViableDevice returns true if the given link is usable and Cilium should attach
// programs to it.
func (dm *DeviceManager) isViableDevice(link netlink.Link) bool {
	name := link.Attrs().Name

	// Do not consider any of the excluded devices.
	for _, p := range excludedDevicePrefixes {
		if strings.HasPrefix(name, p) {
			log.WithField(logfields.Device, name).Debugf("Skipping device as it has excluded prefix '%s'", p)
			return false
		}
	}

	// Skip slave devices.
	if link.Attrs().RawFlags&unix.IFF_SLAVE != 0 {
		log.WithField(logfields.Device, name).Debugf("Skipping slave device")
		return false
	}

	// Ignore L3 devices if we cannot support them.
	if !dm.l3DevOK && !mac.LinkHasMacAddr(link) {
		log.WithField(logfields.Device, name).
			Warn("Ignoring L3 device; >= 5.8 kernel is required.")
		return false
	}

	return true
}

// handleLinkUpdate processes link updates and when detecting a removed device
// it triggers a datapath reload. New devices are detected from routes rather
// than from link updates.
func (dm *DeviceManager) handleLinkUpdate(devicesChangedCallback func(), update netlink.LinkUpdate) {
	if update.Header.Type != unix.RTM_DELLINK {
		return
	}

	newDevices := make([]string, 0, len(option.Config.Devices))
	for _, name := range option.Config.Devices {
		if name != update.Attrs().Name {
			newDevices = append(newDevices, name)
		}
	}

	if len(newDevices) != len(option.Config.Devices) {
		sort.Strings(newDevices)
		option.Config.Devices = newDevices
		if devicesChangedCallback != nil {
			devicesChangedCallback()
		}
	}
}

// updateDevicesFromRoutes processes a batch of routes and sets the option.Config.Devices
// based on the devices found from the routes. This method is shared between the initial
// and runtime device detection.
func (dm *DeviceManager) updateDevicesFromRoutes(devicesChangedCallback func(), routes []netlink.Route) {
	linkIndices := make(map[int]struct{})

	// Collect all links mentioned in the route update batch
	for _, route := range routes {
		// Only consider devices that have global unicast routes,
		// e.g. skip loopback, multicast and link local routes.
		if route.Dst != nil && !route.Dst.IP.IsGlobalUnicast() {
			continue
		}

		linkIndices[route.LinkIndex] = struct{}{}
	}

	newDevices := make([]string, len(option.Config.Devices))
	copy(newDevices, option.Config.Devices)

links:
	for linkIndex := range linkIndices {
		link, err := netlink.LinkByIndex(linkIndex)
		if err != nil {
			log.WithError(err).Warnf("Failed to get link by index %d", linkIndex)
			continue
		}
		name := link.Attrs().Name

		// Skip devices we already know.
		for _, dev := range option.Config.Devices {
			if name == dev {
				continue links
			}
		}

		if dm.isViableDevice(link) {
			newDevices = append(newDevices, name)
		}
	}

	// Update the device list.
	// Use a copy instead of mutating in place to protect concurrent readers.
	if len(newDevices) != len(option.Config.Devices) {
		sort.Strings(newDevices)
		option.Config.Devices = newDevices
		if devicesChangedCallback != nil {
			devicesChangedCallback()
		}
	}
}

// Listen starts listening to changes to network devices. When a new device is
// added or removed it updates option.Config.Devices and calls devicesChangedCallback.
func (dm *DeviceManager) Listen(ctx context.Context, netNS *netns.NsHandle, devicesChangedCallback func()) error {
	routeChan := make(chan netlink.RouteUpdate)
	err := netlink.RouteSubscribeWithOptions(routeChan, dm.closeChan,
		netlink.RouteSubscribeOptions{
			Namespace:    netNS,
			ListExisting: false,
		})
	if err != nil {
		return err
	}

	linkChan := make(chan netlink.LinkUpdate)
	err = netlink.LinkSubscribeWithOptions(linkChan, dm.closeChan, netlink.LinkSubscribeOptions{
		Namespace:    netNS,
		ListExisting: false,
	})
	if err != nil {
		return err
	}

	go func() {
		// If a specific namespace is requested, lock the thread and set the
		// threads namespace. This is currently only relevant for testing.
		if netNS != nil {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := netns.Set(*netNS); err != nil {
				log.WithError(err).Warnf("Failed to set network namespace")
			}
		}

		// To avoid multiple reloads of the datapath when lots of routes are added in one go,
		// collect the route updates into a batch and process the batch every 'minInterval'.
		ticker := time.NewTicker(dm.routeHandlingInterval)
		defer ticker.Stop()
		buffer := make([]netlink.Route, 0)

		for {
			select {
			case <-ctx.Done():
				dm.Close()
				return

			case <-ticker.C:
				if len(buffer) > 0 {
					dm.updateDevicesFromRoutes(devicesChangedCallback, buffer)
					buffer = make([]netlink.Route, 0)
				}

			case update := <-routeChan:
				if update.Type == unix.RTM_NEWROUTE {
					buffer = append(buffer, update.Route)
				}

			case update := <-linkChan:
				dm.handleLinkUpdate(devicesChangedCallback, update)
			}
		}
	}()

	return nil
}

func (dm *DeviceManager) Close() {
	dm.mu.Lock()
	if dm.closeChan != nil {
		close(dm.closeChan)
	}
	dm.closeChan = nil
	dm.mu.Unlock()
}

// Detect tries to detect devices which are to be used for:
// NodePort BPF, direct routing in NodePort BPF, IPsec and Bandwidth Manager.
//
// The devices are detected by looking at all the configured global unicast
// routes in the system.
func (dm *DeviceManager) Detect() error {
	if err := expandDevices(); err != nil {
		log.WithError(err).Warnf("Failed to expand device wildcards")
	}

	// Detect the devices from the system routing table by picking the devices
	// which have global unicast routes.
	if len(option.Config.Devices) == 0 {
		routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
		if err != nil {
			return fmt.Errorf("cannot retrieve routes for device detection: %w", err)
		}
		dm.updateDevicesFromRoutes(nil, routes)
	}
	sort.Strings(option.Config.Devices)

	isDeviceDetected := func(name string) bool {
		return sort.SearchStrings(option.Config.Devices, name) != len(option.Config.Devices)
	}

	detectDirectRoutingDev := option.Config.EnableNodePort && option.Config.DirectRoutingDevice == ""
	detectIPv6MCastDev := option.Config.EnableIPv6NDP && len(option.Config.IPv6MCastDevice) == 0

	// Detect direct routing and IPv6 multicast devices.
	nodeIP := node.GetK8sNodeIP()
	if nodeIP != nil && (detectDirectRoutingDev || detectIPv6MCastDev) {
		for _, dev := range option.Config.Devices {
			link, err := netlink.LinkByName(dev)
			if err != nil {
				return fmt.Errorf("Cannot find device '%s': %w", dev, err)
			}

			// Check if any of the addresses assigned to this device is the k8s node IP and if so
			// use it for direct routing and IPv6 multicast.
			if addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL); err == nil {
				for _, a := range addrs {
					if a.IP.Equal(nodeIP) {
						if detectDirectRoutingDev {
							option.Config.DirectRoutingDevice = dev
							log.Infof("Detected %s=%s", option.DirectRoutingDevice, option.Config.DirectRoutingDevice)
						}
						if detectIPv6MCastDev && link.Attrs().Flags&net.FlagMulticast != 0 {
							option.Config.IPv6MCastDevice = dev
							log.Infof("Detected %s=%s", option.IPv6MCastDevice, option.Config.IPv6MCastDevice)
						}
						break
					}
				}
			} else {
				log.WithError(err).Warnf("Cannot retrieve device '%s' IP addresses, skipping it", dev)
			}
		}

		if detectDirectRoutingDev && option.Config.DirectRoutingDevice == "" {
			return fmt.Errorf("Unable to determine BPF NodePort direct routing device. "+
				"Use --%s to specify it", option.DirectRoutingDevice)
		}
		if detectIPv6MCastDev && option.Config.IPv6MCastDevice == "" {
			return fmt.Errorf("Unable to determine Multicast device. Use --%s to specify them",
				option.IPv6MCastDevice)
		}
	}

	// Validate the configuration.
	// For the principle of least surprise and for catching misbehaviours with the device detection
	// ask the user to specify the devices manually when the direct routing or mcast device is not
	// found among the detected devices.
	//
	// TODO(JM): This is different from earlier where the DirectRouting&IPv6MCast devices were added to
	// the list of devices. Perhaps better not to change this?
	if option.Config.EnableNodePort && option.Config.DirectRoutingDevice != "" {
		if !isDeviceDetected(option.Config.DirectRoutingDevice) {
			return fmt.Errorf("Direct routing device %s was not detected as a valid device. Please specify devices manually with --%s",
				option.Config.DirectRoutingDevice, option.Devices)
		}
	}
	if option.Config.EnableIPv6NDP && option.Config.IPv6MCastDevice != "" {
		if !isDeviceDetected(option.Config.DirectRoutingDevice) {
			return fmt.Errorf("Multicast device %s was not detected as a valid device. Please specify devices manually with --%s",
				option.Config.IPv6MCastDevice, option.Devices)
		}
	}

	log.WithField(logfields.Devices, option.Config.Devices).Info("Detected devices")

	return nil
}

// expandDevices expands all wildcard device names to concrete devices.
// e.g. device "eth+" expands to "eth0,eth1" etc. Non-matching wildcards are ignored.
func expandDevices() error {
	allLinks, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("Cannot list network devices via netlink: %w", err)
	}
	expandedDevices := make(map[string]bool)
	for _, iface := range option.Config.Devices {
		if strings.HasSuffix(iface, "+") {
			prefix := strings.TrimRight(iface, "+")
			for _, link := range allLinks {
				attrs := link.Attrs()
				if strings.HasPrefix(attrs.Name, prefix) {
					expandedDevices[attrs.Name] = true
				}
			}
		} else {
			expandedDevices[iface] = true
		}
	}
	option.Config.Devices = make([]string, 0, len(expandedDevices))
	for dev := range expandedDevices {
		option.Config.Devices = append(option.Config.Devices, dev)
	}
	sort.Strings(option.Config.Devices)
	return nil
}

func supportL3Dev() bool {
	probesManager := probes.NewProbeManager()
	if h := probesManager.GetHelpers("sched_cls"); h != nil {
		_, found := h["bpf_skb_change_head"]
		return found
	}
	return false
}
