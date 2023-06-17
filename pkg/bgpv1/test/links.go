// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
)

// Note : this will work only in linux environment and requires CAP_NET_ADMIN privilege

// dummyInterfaces contains IP addresses for the link
type dummyInterfaces struct {
	ipv4 netip.Prefix
	ipv6 netip.Prefix
}

// default dummy links on which bgp sessions are communicating
var (
	ciliumLink      = "cilium-bgp"
	instance1Link   = "instance1"
	instance2Link   = "instance2"
	ciliumIPEnv     = "CiliumPrefix"
	ciliumIP6Env    = "CiliumPrefix6"
	instance1IPEnv  = "Instance1Prefix"
	instance1IP6Env = "Instance1Prefix6"
	instance2IPEnv  = "Instance2Prefix"
	instance2IP6Env = "Instance2Prefix6"
	dummies         = map[string]dummyInterfaces{
		// link used by BGP Control Plane
		ciliumLink: {
			ipv4: getIP(ciliumIPEnv, "172.16.100.1/32"),
			ipv6: getIP(ciliumIP6Env, "a::1/128"),
		},
		// link used by gobgp instance 1
		instance1Link: {
			ipv4: getIP(instance1IPEnv, "172.16.100.2/32"),
			ipv6: getIP(instance1IP6Env, "a::2/128"),
		},
		// link used by gobgp instance 2
		instance2Link: {
			ipv4: getIP(instance2IPEnv, "172.16.100.3/32"),
			ipv6: getIP(instance2IP6Env, "a::3/128"),
		},
	}
)

// getIP gets Prefix from env if set, otherwise returns default values.
var getIP = func(envPrefix, defPrefix string) netip.Prefix {
	ip := os.Getenv(envPrefix)
	if ip != "" {
		return netip.MustParsePrefix(ip)
	} else {
		return netip.MustParsePrefix(defPrefix)
	}
}

// setupLinks creates links defined in dummies
func setupLinks() error {
	log.Info("adding dummy links")

	for name := range dummies {
		err := netlink.LinkAdd(&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: name,
			},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// teardownLinks deletes links defined in dummies
func teardownLinks() error {
	log.Info("deleting dummy links")

	for name := range dummies {
		err := netlink.LinkDel(&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: name,
			},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// setupLinkIPs configures IPs and set links up which are defined in setupLinkIPs
func setupLinkIPs() error {
	for name, dummy := range dummies {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}

		err = netlink.AddrAdd(l, toNetlinkAddr(dummy.ipv4))
		if err != nil {
			return err
		}

		err = netlink.AddrAdd(l, toNetlinkAddr(dummy.ipv6))
		if err != nil {
			return err
		}

		err = netlink.LinkSetUp(l)
		if err != nil {
			return err
		}
	}

	return nil
}

// toNetlinkAddr converts netip.Prefix to *netlink.Addr
func toNetlinkAddr(prefix netip.Prefix) *netlink.Addr {
	pLen := 128
	if prefix.Addr().Is4() {
		pLen = 32
	}
	return &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), pLen),
		},
	}
}
