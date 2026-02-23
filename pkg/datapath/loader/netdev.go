// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// bpfMasqAddrs returns the IPv4 and IPv6 masquerade addresses to be used for
// the given interface name according to the provided LocalNodeConfiguration.
//
// If no suitable address is found for the given interface, fall back to
// searching for addresses on the wildcard device name.
func bpfMasqAddrs(ifName string, cfg *datapath.LocalNodeConfiguration, enable4, enable6 bool) (masq4, masq6 netip.Addr) {
	if cfg.DeriveMasqIPAddrFromDevice != "" {
		ifName = cfg.DeriveMasqIPAddrFromDevice
	}

	if enable4 {
		masq4 = primaryV4(ifName, cfg.NodeAddresses)
		if !masq4.IsValid() {
			masq4 = primaryV4(tables.WildcardDeviceName, cfg.NodeAddresses)
		}
	}

	if enable6 {
		masq6 = primaryV6(ifName, cfg.NodeAddresses)
		if !masq6.IsValid() {
			masq6 = primaryV6(tables.WildcardDeviceName, cfg.NodeAddresses)
		}
	}

	return
}

func primaryV4(ifName string, addrs []tables.NodeAddress) netip.Addr {
	for _, addr := range addrs {
		if !addr.Primary || addr.DeviceName != ifName {
			continue
		}
		if addr.Addr.Is4() {
			return addr.Addr
		}
	}
	return netip.Addr{}
}

func primaryV6(ifName string, addrs []tables.NodeAddress) netip.Addr {
	for _, addr := range addrs {
		if !addr.Primary || addr.DeviceName != ifName {
			continue
		}
		if addr.Addr.Is6() {
			return addr.Addr
		}
	}
	return netip.Addr{}
}

func isObsoleteDev(dev string, devices []string) bool {
	// exclude devices we never attach to/from_netdev to.
	for _, prefix := range defaults.ExcludedDevicePrefixes {
		if strings.HasPrefix(dev, prefix) {
			return false
		}
	}

	// exclude devices that will still be managed going forward.
	return !slices.Contains(devices, dev)
}

// removeObsoleteNetdevPrograms removes cil_to_netdev and cil_from_netdev from devices
// that cilium potentially doesn't manage anymore after a restart, e.g. if the set of
// devices changes between restarts.
//
// This code assumes that the agent was upgraded from a prior version while maintaining
// the same list of managed physical devices. This ensures that all tc bpf filters get
// replaced using the naming convention of the 'current' agent build. For example,
// before 1.13, most filters were named e.g. bpf_host.o:[to-host], to be changed to
// cilium-<device> in 1.13, then to cil_to_host-<device> in 1.14. As a result, this
// function only cleans up filters following the current naming scheme.
func removeObsoleteNetdevPrograms(logger *slog.Logger, devices []string) error {
	links, err := safenetlink.LinkList()
	if err != nil {
		return fmt.Errorf("retrieving all netlink devices: %w", err)
	}

	// collect all devices that have netdev programs attached on either ingress or egress.
	ingressDevs := []netlink.Link{}
	egressDevs := []netlink.Link{}
	for _, l := range links {
		if !isObsoleteDev(l.Attrs().Name, devices) {
			continue
		}

		// Remove the per-device bpffs directory containing pinned links and
		// per-endpoint maps.
		bpffsPath := bpffsDeviceDir(bpf.CiliumPath(), l)
		if err := bpf.Remove(bpffsPath); err != nil {
			logger.Error("Failed to remove bpffs entry",
				logfields.Error, err,
				logfields.BPFFSPath, bpffsPath,
			)
		}

		// Remove the per-device state directory.
		statePath := bpfStateDeviceDir(l.Attrs().Name)
		if err := os.RemoveAll(statePath); err != nil {
			logger.Error("Failed to remove device state directory",
				logfields.Error, err,
				logfields.Path, statePath,
			)
		}

		ingressFilters, err := safenetlink.FilterList(l, directionToParent(dirIngress))
		if err != nil {
			return fmt.Errorf("listing ingress filters: %w", err)
		}
		for _, filter := range ingressFilters {
			if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
				if strings.HasPrefix(bpfFilter.Name, symbolFromHostNetdevEp) {
					ingressDevs = append(ingressDevs, l)
				}
			}
		}

		egressFilters, err := safenetlink.FilterList(l, directionToParent(dirEgress))
		if err != nil {
			return fmt.Errorf("listing egress filters: %w", err)
		}
		for _, filter := range egressFilters {
			if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
				if strings.HasPrefix(bpfFilter.Name, symbolToHostNetdevEp) {
					egressDevs = append(egressDevs, l)
				}
			}
		}
	}

	for _, dev := range ingressDevs {
		err = removeTCFilters(dev, directionToParent(dirIngress))
		if err != nil {
			logger.Error(
				"couldn't remove ingress tc filters",
				logfields.Error, err,
				logfields.Device, dev.Attrs().Name,
			)
		}
	}

	for _, dev := range egressDevs {
		err = removeTCFilters(dev, directionToParent(dirEgress))
		if err != nil {
			logger.Error(
				"couldn't remove egress tc filters",
				logfields.Error, err,
				logfields.Device, dev.Attrs().Name,
			)
		}
	}

	return nil
}
