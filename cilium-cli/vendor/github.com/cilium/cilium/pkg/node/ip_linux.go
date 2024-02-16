// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"strings"

	"github.com/vishvananda/netlink"
)

func init() {
	initExcludedIPs()
}

func initExcludedIPs() {
	// We exclude below bad device prefixes from address selection ...
	prefixes := []string{
		"docker",
	}
	links, err := netlink.LinkList()
	if err != nil {
		return
	}
	for _, l := range links {
		// ... also all down devices since they won't be reachable.
		//
		// We need to check for both "up" and "unknown" state, as some
		// drivers may not implement operstate handling, and just report
		// their state as unknown even though they are operational.
		if l.Attrs().OperState == netlink.OperUp ||
			l.Attrs().OperState == netlink.OperUnknown {
			skip := true
			for _, p := range prefixes {
				if strings.HasPrefix(l.Attrs().Name, p) {
					skip = false
					break
				}
			}
			if skip {
				continue
			}
		}
		addr, err := netlink.AddrList(l, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, a := range addr {
			excludedIPs = append(excludedIPs, a.IP)
		}
	}
}
