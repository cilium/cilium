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
)

// listVethIfaces returns a map of VETH interfaces with the index as key.
func listVethIfaces() (map[int]netlink.Link, error) {
	ifs, err := safenetlink.LinkList()
	if err != nil {
		return nil, err
	}

	vethLXCIdxs := map[int]netlink.Link{}
	for _, intf := range ifs {
		if intf.Type() == "veth" {
			vethLXCIdxs[intf.Attrs().Index] = intf
		}
	}

	return vethLXCIdxs, nil
}

// clearCiliumVeths checks all veths created by cilium and removes all that
// are considered a leftover from failed attempts to connect the container.
func clearCiliumVeths(logger *slog.Logger) error {
	logger.Info("Removing stale endpoint interfaces")

	vethIfaces, err := listVethIfaces()
	if err != nil {
		return fmt.Errorf("unable to retrieve veth interfaces on host: %w", err)
	}

	for _, v := range vethIfaces {
		peerIndex := v.Attrs().ParentIndex
		peerVeth, peerFoundInHostNamespace := vethIfaces[peerIndex]

		// In addition to name matching, double check whether the parent of the
		// parent is the interface itself, to avoid removing the interface in
		// case we hit an index clash, and the actual parent of the interface is
		// in a different network namespace. Notably, this can happen in the
		// context of Kind nodes, as eth0 is a veth interface itself; if an
		// lxcxxxxxx interface ends up having the same ifindex of the eth0 parent
		// (which is actually located in the root network namespace), we would
		// otherwise end up deleting the eth0 interface, with the obvious
		// ill-fated consequences.
		if peerFoundInHostNamespace &&
			peerIndex != 0 &&
			strings.HasPrefix(peerVeth.Attrs().Name, "lxc") &&
			peerVeth.Attrs().ParentIndex == v.Attrs().Index {

			scopedLog := logger.With(
				logfields.Index, v.Attrs().Index,
				logfields.Device, v.Attrs().Name,
			)

			scopedLog.Debug("Deleting stale veth device")

			if err := netlink.LinkDel(v); err != nil {
				scopedLog.Warn("Unable to delete stale veth device", logfields.Error, err)
			}
		}
	}

	return nil
}
