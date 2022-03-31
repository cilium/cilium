// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func ethtoolCommands() []string {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	sources := make([]string, 0, len(links)*2)
	for _, link := range links {
		// query current settings
		sources = append(sources, fmt.Sprintf("ethtool %s", link.Attrs().Name))
		// query for driver information
		sources = append(sources, fmt.Sprintf("ethtool -i %s", link.Attrs().Name))
	}
	return sources
}
