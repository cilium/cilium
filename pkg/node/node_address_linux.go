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

	"github.com/vishvananda/netlink"
)

// firstGlobalV4Addr  returns the first IP address for the given interface, if
// the wishIP is send it'll return the wishIP if is in the list of address.
func firstGlobalV4Addr(intf string, wishIP net.IP) (net.IP, error) {
	var link netlink.Link
	var err error

	if intf != "" && intf != "undefined" {
		link, err = netlink.LinkByName(intf)
		if err != nil {
			return firstGlobalV4Addr("", wishIP)
		}
	}

	addr, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	ips := []net.IP{}

	for _, a := range addr {
		if a.Scope == unix.RT_SCOPE_UNIVERSE {
			if len(a.IP) >= 4 {
				ips = append(ips, a.IP)
				// If the IP is the same as the  wishIP, that means that maybe
				// is restored from node_config.h, so if it is present we
				// continue using this one.
				if a.IP.Equal(wishIP) {
					return a.IP, nil
				}
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("No address found")
	}

	// Just make sure that we always return the same one and no a random one.
	// More info in the issue GH-76	37
	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(ips[i], ips[j]) < 0
	})

	return ips[0], nil
}

// findIPv6NodeAddr returns the first IPv6 IP in the node, if the wishIP is
// present it's the one that it's going to be returned.
func findIPv6NodeAddr(wishIP net.IP) net.IP {
	addr, err := netlink.AddrList(nil, netlink.FAMILY_V6)
	if err != nil {
		return nil
	}

	ips := []net.IP{}
	// prefer global scope address
	for _, a := range addr {
		if a.Scope == unix.RT_SCOPE_UNIVERSE {
			if len(a.IP) >= 16 {
				ips = append(ips, a.IP)

				// If the IP is the same as the  wishIP, that means that maybe
				// is restored from node_config.h, so if it is present we
				// continue using this one.
				if a.IP.Equal(wishIP) {
					return a.IP
				}
			}
		}
	}

	if len(ips) > 0 {
		// Just make sure that we always return the same one and no a random one.
		// More info in the issue GH-76	37
		sort.Slice(ips, func(i, j int) bool {
			return bytes.Compare(ips[i], ips[j]) < 0
		})
		return ips[0]
	}

	// fall back to anything wider than link (site, custom, ...)
	for _, a := range addr {
		if a.Scope < unix.RT_SCOPE_LINK {
			if len(a.IP) >= 16 {
				ips = append(ips, a.IP)
				// If the IP is the same as the  wishIP, that means that maybe
				// is restored from node_config.h, so if it is present we
				// continue using this one.
				if a.IP.Equal(wishIP) {
					return a.IP
				}
			}
		}
	}
	if len(ips) == 0 {
		return nil
	}
	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(ips[i], ips[j]) < 0
	})

	return ips[0]
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
