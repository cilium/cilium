// +build linux

package cmd

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func ethoolCommands() []string {
	sources := []string{}
	// Append ethtool links
	if links, err := netlink.LinkList(); err == nil {
		for _, link := range links {
			// query current settings
			sources = append(sources, fmt.Sprintf("ethtool %s", link.Attrs().Name))
			// query for driver information
			sources = append(sources, fmt.Sprintf("ethtool -i %s", link.Attrs().Name))
		}
	}

	return sources
}
