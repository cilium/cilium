// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netdevice

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

func GetIfaceFirstIPv4Address(ifaceName string) (netip.Addr, error) {
	dev, err := safenetlink.LinkByName(ifaceName)
	if err != nil {
		return netip.Addr{}, err
	}

	addrs, err := safenetlink.AddrList(dev, netlink.FAMILY_V4)
	if err != nil {
		return netip.Addr{}, err
	}

	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			a, ok := netipx.FromStdIP(addr.IP)
			if !ok {
				continue
			}
			return a, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("no IPv4 address assigned to interface")
}

func TestForIfaceWithIPv4Address(ip netip.Addr) error {
	_, err := getIfaceWithIPv4Address(ip)
	return err
}

func GetIfaceWithIPv4Address(ip netip.Addr) (string, error) {
	return getIfaceWithIPv4Address(ip)
}

func getIfaceWithIPv4Address(ip netip.Addr) (string, error) {
	links, err := safenetlink.LinkList()
	if err != nil {
		return "", err
	}

	for _, l := range links {
		addrs, err := safenetlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			a, ok := netipx.FromStdIP(addr.IP)
			if !ok {
				continue
			}
			if a == ip {
				return l.Attrs().Name, nil
			}
		}
	}

	return "", fmt.Errorf("no interface with %s IPv4 assigned to", ip)
}

func GetIfaceFirstIPv6Address(ifaceName string) (netip.Addr, error) {
	dev, err := safenetlink.LinkByName(ifaceName)
	if err != nil {
		return netip.Addr{}, err
	}

	addrs, err := safenetlink.AddrList(dev, netlink.FAMILY_V6)
	if err != nil {
		return netip.Addr{}, err
	}

	for _, addr := range addrs {
		if addr.IP.To4() == nil && addr.IP.To16() != nil {
			a, ok := netipx.FromStdIP(addr.IP)
			if !ok {
				continue
			}
			if a.IsLinkLocalUnicast() {
				continue
			}
			return a, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("no IPv6 address assigned to interface")
}

func GetIfaceWithIPv6Address(ip netip.Addr) (string, error) {
	links, err := safenetlink.LinkList()
	if err != nil {
		return "", err
	}

	for _, l := range links {
		addrs, err := safenetlink.AddrList(l, netlink.FAMILY_V6)
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			if addr.IP.To4() == nil && addr.IP.To16() != nil {
				a, ok := netipx.FromStdIP(addr.IP)
				if !ok {
					continue
				}
				if a == ip {
					return l.Attrs().Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no interface with %s IPv6 assigned to", ip)
}
