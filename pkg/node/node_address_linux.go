// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// +build !darwin

package node

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ip"

	"github.com/vishvananda/netlink"
)

func firstGlobalAddr(intf string, preferredIP net.IP, family int) (net.IP, error) {
	var link netlink.Link
	var ipLen int
	var err error

	ipsToExclude := ip.GetExcludedIPs()
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
	ipsPublic := []net.IP{}
	ipsPrivate := []net.IP{}
	hasPreferred := false

	for _, a := range addr {
		if a.Scope <= linkScopeMax {
			if ip.IsExcluded(ipsToExclude, a.IP) {
				continue
			}
			if len(a.IP) >= ipLen {
				if ip.IsPublicAddr(a.IP) {
					ipsPublic = append(ipsPublic, a.IP)
				} else {
					ipsPrivate = append(ipsPrivate, a.IP)
				}
				// If the IP is the same as the preferredIP, that
				// means that maybe it is restored from node_config.h,
				// so if it is present we prefer this one.
				if a.IP.Equal(preferredIP) {
					hasPreferred = true
				}
			}
		}
	}

	if len(ipsPublic) != 0 {
		if hasPreferred && ip.IsPublicAddr(preferredIP) {
			return preferredIP, nil
		}

		// Just make sure that we always return the same one and not a
		// random one. More info in the issue GH-7637.
		sort.Slice(ipsPublic, func(i, j int) bool {
			return bytes.Compare(ipsPublic[i], ipsPublic[j]) < 0
		})

		return ipsPublic[0], nil
	}

	if len(ipsPrivate) != 0 {
		if hasPreferred && !ip.IsPublicAddr(preferredIP) {
			return preferredIP, nil
		}

		// Same stable order, see above ipsPublic.
		sort.Slice(ipsPrivate, func(i, j int) bool {
			return bytes.Compare(ipsPrivate[i], ipsPrivate[j]) < 0
		})

		return ipsPrivate[0], nil
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
// where the IPs are sorted in ascending order.
//
// Public IPs are preferred over private ones. When intf is defined only
// IPs belonging to that interface are considered.
//
// If preferredIP is present in the IP list it is returned irrespective of
// the sort order. However, if preferredIP is a private IP and there are
// public IPs, then public one is selected.
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
func firstGlobalV4Addr(intf string, preferredIP net.IP) (net.IP, error) {
	return firstGlobalAddr(intf, preferredIP, netlink.FAMILY_V4)
}

// firstGlobalV6Addr returns first IPv6 global IP of an interface, see
// firstGlobalV4Addr for more details.
func firstGlobalV6Addr(intf string, preferredIP net.IP) (net.IP, error) {
	return firstGlobalAddr(intf, preferredIP, netlink.FAMILY_V6)
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
	return ipv4GW, ipv6Router
}

// SetInternalIPv4From sets the internal IPv4 with the first global address
// found in that interface.
func SetInternalIPv4From(ifaceName string) error {
	l, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return errors.New("unable to retrieve interface attributes")
	}
	v4Addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
	if err != nil {
		return errors.New("unable to retrieve interface IPv4 address")
	}
	for _, ip := range v4Addrs {
		if netlink.Scope(ip.Scope) == netlink.SCOPE_UNIVERSE {
			SetInternalIPv4(ip.IP)
			return nil
		}
	}
	return errors.New("unable to find IP addresses with scope global")
}
