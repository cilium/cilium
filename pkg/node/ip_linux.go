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
		// Don't exclude dummy devices, since they may be setup by
		// processes like nodelocaldns and they aren't always brought up. See
		// https://github.com/kubernetes/dns/blob/fa0192f004c9571cf24d8e9868be07f57380fccb/pkg/netif/netif.go#L24-L36
		// Such devices in down state may still be relevant.
		if l.Type() == "dummy" {
			continue
		}
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
