// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !darwin

package node

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/testutils"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"
)

type NodePrivilegedSuite struct{}

var _ = Suite(&NodePrivilegedSuite{})

func (s *NodePrivilegedSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
}

func (s *NodePrivilegedSuite) Test_firstGlobalV4Addr(c *C) {
	testCases := []struct {
		name           string
		ipsOnInterface []string
		preferredIP    string
		preferPublic   bool
		want           string
	}{
		{
			name:           "public IP preferred by default",
			ipsOnInterface: []string{"192.168.0.1", "21.0.0.1"},
			want:           "21.0.0.1",
		},
		{
			name:           "prefer IP when not preferPublic",
			ipsOnInterface: []string{"192.168.0.1", "21.0.0.1"},
			preferredIP:    "192.168.0.1",
			want:           "192.168.0.1",
		},
		{
			name:           "preferPublic when not prefer IP",
			ipsOnInterface: []string{"192.168.0.1", "21.0.0.1"},
			preferPublic:   true,
			want:           "21.0.0.1",
		},
		{
			name:           "preferPublic when prefer IP",
			ipsOnInterface: []string{"192.168.0.1", "21.0.0.1"},
			preferPublic:   true,
			preferredIP:    "192.168.0.1",
			want:           "21.0.0.1",
		},
		{
			name:           "primary IP preferred by default",
			ipsOnInterface: []string{"192.168.0.2", "192.168.0.1"},
			want:           "192.168.0.2",
		},
	}
	const ifName = "dummy_iface"
	for _, tc := range testCases {
		err := setupDummyDevice(ifName, tc.ipsOnInterface...)
		c.Assert(err, IsNil)

		got, err := firstGlobalV4Addr(ifName, net.ParseIP(tc.preferredIP), tc.preferPublic)
		if err != nil {
			c.Error(err)
		} else {
			c.Check(tc.want, Equals, got.String())
		}
		removeDevice(ifName)
	}
}

func setupDummyDevice(name string, ips ...string) error {
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		return fmt.Errorf("netlink.LinkAdd failed: %v", err)
	}

	if err := netlink.LinkSetUp(dummy); err != nil {
		removeDevice(name)
		return fmt.Errorf("netlink.LinkSetUp failed: %v", err)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			removeDevice(name)
			return fmt.Errorf("invalid ipv4 IP : %v", ipStr)
		}
		ipnet := &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		addr := &netlink.Addr{IPNet: ipnet}
		if err := netlink.AddrAdd(dummy, addr); err != nil {
			removeDevice(name)
			return err
		}
	}

	return nil
}

func removeDevice(name string) {
	l, err := netlink.LinkByName(name)
	if err == nil {
		netlink.LinkDel(l)
	}
}
