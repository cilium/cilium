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
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
)

func firstGlobalV4Addr(intf string) (net.IP, error) {
	var link netlink.Link
	var err error

	if intf != "" && intf != "undefined" {
		link, err = netlink.LinkByName(intf)
		if err != nil {
			return firstGlobalV4Addr("")
		}
	}

	addr, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	for _, a := range addr {
		if a.Scope == unix.RT_SCOPE_UNIVERSE {
			if len(a.IP) >= 4 {
				return a.IP, nil
			}
		}
	}

	return nil, fmt.Errorf("No address found")
}

func findIPv6NodeAddr() net.IP {
	addr, err := netlink.AddrList(nil, netlink.FAMILY_V6)
	if err != nil {
		return nil
	}

	// prefer global scope address
	for _, a := range addr {
		if a.Scope == unix.RT_SCOPE_UNIVERSE {
			if len(a.IP) >= 16 {
				return a.IP
			}
		}
	}

	// fall back to anything wider than link (site, custom, ...)
	for _, a := range addr {
		if a.Scope < unix.RT_SCOPE_LINK {
			if len(a.IP) >= 16 {
				return a.IP
			}
		}
	}

	return nil
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
