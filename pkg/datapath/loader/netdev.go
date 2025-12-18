// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

func bpfMasqAddrs(ifName string, cfg *datapath.LocalNodeConfiguration) (masq4, masq6 netip.Addr) {
	if cfg.DeriveMasqIPAddrFromDevice != "" {
		ifName = cfg.DeriveMasqIPAddrFromDevice
	}

	find := func(devName string) bool {
		for _, addr := range cfg.NodeAddresses {
			if addr.DeviceName != devName {
				continue
			}
			if !addr.Primary {
				continue
			}
			if addr.Addr.Is4() && !masq4.IsValid() {
				masq4 = addr.Addr
			} else if addr.Addr.Is6() && !masq6.IsValid() {
				masq6 = addr.Addr
			}
			done := (!option.Config.EnableIPv4Masquerade || masq4.IsValid()) &&
				(!option.Config.EnableIPv6Masquerade || masq6.IsValid())
			if done {
				return true
			}
		}
		return false
	}

	// Try to find suitable masquerade address first from the given interface.
	if !find(ifName) {
		// No suitable masquerade addresses were found for this device. Try the fallback
		// addresses.
		find(tables.WildcardDeviceName)
	}

	return
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
				logfields.BPFSPath, bpffsPath,
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
