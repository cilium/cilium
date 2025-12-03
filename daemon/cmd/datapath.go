// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/option"
)

// listFilterIfs returns a map of interfaces based on the given filter.
// The filter should take a link and, if found, return the index of that
// interface, if not found return -1.
func listFilterIfs(filter func(netlink.Link) int) (map[int]netlink.Link, error) {
	ifs, err := safenetlink.LinkList()
	if err != nil {
		return nil, err
	}
	vethLXCIdxs := map[int]netlink.Link{}
	for _, intf := range ifs {
		if idx := filter(intf); idx != -1 {
			vethLXCIdxs[idx] = intf
		}
	}
	return vethLXCIdxs, nil
}

// clearCiliumVeths checks all veths created by cilium and removes all that
// are considered a leftover from failed attempts to connect the container.
func clearCiliumVeths(logger *slog.Logger) error {
	logger.Info("Removing stale endpoint interfaces")

	leftVeths, err := listFilterIfs(func(intf netlink.Link) int {
		// Filter by veth and return the index of the interface.
		if intf.Type() == "veth" {
			return intf.Attrs().Index
		}
		return -1
	})
	if err != nil {
		return fmt.Errorf("unable to retrieve host network interfaces: %w", err)
	}

	for _, v := range leftVeths {
		peerIndex := v.Attrs().ParentIndex
		parentVeth, found := leftVeths[peerIndex]

		// In addition to name matching, double check whether the parent of the
		// parent is the interface itself, to avoid removing the interface in
		// case we hit an index clash, and the actual parent of the interface is
		// in a different network namespace. Notably, this can happen in the
		// context of Kind nodes, as eth0 is a veth interface itself; if an
		// lxcxxxxxx interface ends up having the same ifindex of the eth0 parent
		// (which is actually located in the root network namespace), we would
		// otherwise end up deleting the eth0 interface, with the obvious
		// ill-fated consequences.
		if found && peerIndex != 0 && strings.HasPrefix(parentVeth.Attrs().Name, "lxc") &&
			parentVeth.Attrs().ParentIndex == v.Attrs().Index {
			scopedLog := logger.With(logfields.Device, v.Attrs().Name)

			scopedLog.Debug("Deleting stale veth device")
			err := netlink.LinkDel(v)
			if err != nil {
				scopedLog.Warn("Unable to delete stale veth device", logfields.Error, err)
			}
		}
	}
	return nil
}

// initMaps opens all BPF maps (and creates them if they do not exist). This
// must be done *before* any operations which read BPF maps, especially
// restoring endpoints and services.
func initMaps(params daemonParams) error {
	if option.Config.DryMode {
		return nil
	}

	if err := lxcmap.LXCMap(params.MetricsRegistry).OpenOrCreate(); err != nil {
		return fmt.Errorf("initializing lxc map: %w", err)
	}

	for _, m := range ctmap.GlobalMaps(option.Config.EnableIPv4,
		option.Config.EnableIPv6) {
		if err := m.Create(); err != nil {
			return fmt.Errorf("initializing conntrack map %s: %w", m.Name(), err)
		}
	}

	ipv4Nat, ipv6Nat := nat.GlobalMaps(params.MetricsRegistry, option.Config.EnableIPv4,
		option.Config.EnableIPv6, params.KPRConfig.KubeProxyReplacement || option.Config.EnableBPFMasquerade)
	if ipv4Nat != nil {
		if err := ipv4Nat.Create(); err != nil {
			return fmt.Errorf("initializing ipv4nat map: %w", err)
		}
	}
	if ipv6Nat != nil {
		if err := ipv6Nat.Create(); err != nil {
			return fmt.Errorf("initializing ipv6nat map: %w", err)
		}
	}

	if params.KPRConfig.KubeProxyReplacement {
		if err := neighborsmap.InitMaps(option.Config.EnableIPv4,
			option.Config.EnableIPv6); err != nil {
			return fmt.Errorf("initializing neighbors map: %w", err)
		}
	}
	if params.KPRConfig.KubeProxyReplacement || option.Config.EnableBPFMasquerade {
		if err := nat.CreateRetriesMaps(option.Config.EnableIPv4,
			option.Config.EnableIPv6); err != nil {
			return fmt.Errorf("initializing NAT retries map: %w", err)
		}
	}

	if !option.Config.RestoreState {
		// If we are not restoring state, all endpoints can be
		// deleted. Entries will be re-populated.
		lxcmap.LXCMap(params.MetricsRegistry).DeleteAll()
	}

	return nil
}
