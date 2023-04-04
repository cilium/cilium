// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !darwin

package node

import (
	"fmt"
	"net"
	"sort"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ip"
)

func firstGlobalAddr(intf string, preferredIP net.IP, family int, preferPublic bool) (net.IP, error) {
	var link netlink.Link
	var ipLen int
	var err error

	ipsToExclude := GetExcludedIPs()
	linkScopeMax := unix.RT_SCOPE_UNIVERSE
	if family == netlink.FAMILY_V4 {
		ipLen = 4
	} else {
		ipLen = 16
	}

	if intf != "" && intf != "undefined" {
		link, err = netlink.LinkByName(intf)
		if err != nil {
			link = nil
		} else {
			ipsToExclude = []net.IP{}
		}
	}

retryInterface:
	addr, err := netlink.AddrList(link, family)
	if err != nil {
		return nil, err
	}

retryScope:
	ipsPublic := []netlink.Addr{}
	ipsPrivate := []netlink.Addr{}
	hasPreferred := false

	for _, a := range addr {
		if a.Scope > linkScopeMax {
			continue
		}
		if ip.ListContainsIP(ipsToExclude, a.IP) {
			continue
		}
		if len(a.IP) < ipLen {
			continue
		}
		isPreferredIP := a.IP.Equal(preferredIP)
		if a.Flags&unix.IFA_F_SECONDARY > 0 && !isPreferredIP {
			// Skip secondary addresses if they're not the preferredIP
			continue
		}

		if ip.IsPublicAddr(a.IP) {
			ipsPublic = append(ipsPublic, a)
		} else {
			ipsPrivate = append(ipsPrivate, a)
		}
		// If the IP is the same as the preferredIP, that
		// means that maybe it is restored from node_config.h,
		// so if it is present we prefer this one, even if it
		// is a secondary address.
		if isPreferredIP {
			hasPreferred = true
		}
	}

	if hasPreferred && !preferPublic {
		return preferredIP, nil
	}

	if len(ipsPublic) != 0 {
		if hasPreferred && ip.IsPublicAddr(preferredIP) {
			return preferredIP, nil
		}

		// Just make sure that we always return the same one and not a
		// random one. More info in the issue GH-7637.
		sort.SliceStable(ipsPublic, func(i, j int) bool {
			return ipsPublic[i].LinkIndex < ipsPublic[j].LinkIndex
		})

		return ipsPublic[0].IP, nil
	}

	if len(ipsPrivate) != 0 {
		if hasPreferred && !ip.IsPublicAddr(preferredIP) {
			return preferredIP, nil
		}

		// Same stable order, see above ipsPublic.
		sort.SliceStable(ipsPrivate, func(i, j int) bool {
			return ipsPrivate[i].LinkIndex < ipsPrivate[j].LinkIndex
		})

		return ipsPrivate[0].IP, nil
	}

	// First, if a device is specified, fall back to anything wider
	// than link (site, custom, ...) before trying all devices.
	if linkScopeMax != unix.RT_SCOPE_SITE {
		linkScopeMax = unix.RT_SCOPE_SITE
		goto retryScope
	}

	// Fall back with retry for all interfaces with full scope again
	// (which then goes back to lower scope again for all interfaces
	// before we give up completely).
	if link != nil {
		linkScopeMax = unix.RT_SCOPE_UNIVERSE
		link = nil
		goto retryInterface
	}

	return nil, fmt.Errorf("No address found")
}

// firstGlobalV4Addr returns the first IPv4 global IP of an interface,
// where the IPs are sorted in creation order (oldest to newest).
//
// All secondary IPs, except the preferredIP, are filtered out.
//
// Public IPs are preferred over private ones. When intf is defined only
// IPs belonging to that interface are considered.
//
// If preferredIP is present in the IP list it is returned irrespective of
// the sort order. However, if preferPublic is true and preferredIP is a
// private IP, a public IP will be returned if it is assigned to the intf
//
// Passing intf and preferredIP will only return preferredIP if it is in
// the IPs that belong to intf.
//
// In all cases, if intf is not found all interfaces are considered.
//
// If a intf-specific global address couldn't be found, we retry to find
// an address with reduced scope (site, custom) on that particular device.
//
// If the latter fails as well, we retry on all interfaces beginning with
// universe scope again (and then falling back to reduced scope).
//
// In case none of the above helped, we bail out with error.
func firstGlobalV4Addr(intf string, preferredIP net.IP, preferPublic bool) (net.IP, error) {
	return firstGlobalAddr(intf, preferredIP, netlink.FAMILY_V4, preferPublic)
}

// firstGlobalV6Addr returns first IPv6 global IP of an interface, see
// firstGlobalV4Addr for more details.
func firstGlobalV6Addr(intf string, preferredIP net.IP, preferPublic bool) (net.IP, error) {
	return firstGlobalAddr(intf, preferredIP, netlink.FAMILY_V6, preferPublic)
}

// getCiliumHostIPsFromNetDev returns the first IPv4 link local and returns
// it
func getCiliumHostIPsFromNetDev(devName string) (ipv4GW, ipv6Router net.IP) {
	hostDev, err := netlink.LinkByName(devName)
	if err != nil {
		return nil, nil
	}
	addrs, err := netlink.AddrList(hostDev, netlink.FAMILY_ALL)
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

	if ipv4GW != nil || ipv6Router != nil {
		log.WithFields(logrus.Fields{
			"ipv4":   ipv4GW,
			"ipv6":   ipv6Router,
			"device": devName,
		}).Info("Restored router address from device")
	}

	return ipv4GW, ipv6Router
}
