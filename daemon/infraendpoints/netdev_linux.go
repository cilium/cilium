// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

// getCiliumHostIPsFromNetDev returns the first IPv4 link local and returns it
func getCiliumHostIPsFromNetDev(devName string) (ipv4GW, ipv6Router net.IP) {
	hostDev, err := safenetlink.LinkByName(devName)
	if err != nil {
		return nil, nil
	}
	addrs, err := safenetlink.AddrList(hostDev, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil
	}
	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			if addr.Scope == int(netlink.SCOPE_LINK) {
				ipv4GW = addr.IP
			}
		} else {
			if addr.Scope != int(netlink.SCOPE_LINK) {
				ipv6Router = addr.IP
			}
		}
	}

	return ipv4GW, ipv6Router
}
