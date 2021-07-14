// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2019 Authors of Cilium

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
		if l.Attrs().OperState == netlink.OperUp {
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
