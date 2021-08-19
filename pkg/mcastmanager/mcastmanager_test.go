// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package mcastmanager

import (
	"testing"

	"github.com/cilium/cilium/pkg/addressing"
	"github.com/vishvananda/netlink"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type McastManagerSuite struct {
}

var _ = Suite(&McastManagerSuite{})

func (m *McastManagerSuite) TestAddRemoveEndpoint(c *C) {
	ifaces, err := netlink.LinkList()
	c.Assert(err, IsNil)

	if len(ifaces) == 0 {
		c.Skip("no interfaces to test")
	}

	var (
		ok bool

		iface = ifaces[0]
		mgr   = New(iface.Attrs().Name)
	)

	// Add first endpoint
	mgr.AddAddress(ipv6("f00d::1234"))

	c.Assert(mgr.state, HasLen, 1)
	_, ok = mgr.state["ff02::1:ff00:1234"]
	c.Assert(ok, Equals, true)

	// Add another endpoint that shares the same maddr
	mgr.AddAddress(ipv6("f00d:aabb::1234"))

	c.Assert(mgr.state, HasLen, 1)

	// Remove the first endpoint
	mgr.RemoveAddress(ipv6("f00d::1234"))

	c.Assert(mgr.state, HasLen, 1)
	_, ok = mgr.state["ff02::1:ff00:1234"]
	c.Assert(ok, Equals, true)

	// Remove the second endpoint
	mgr.RemoveAddress(ipv6("f00d:aabb::1234"))

	c.Assert(mgr.state, HasLen, 0)
	_, ok = mgr.state["ff02::1:ff00:1234"]
	c.Assert(ok, Equals, false)
}

func (m *McastManagerSuite) TestAddRemoveNil(c *C) {
	ifaces, err := netlink.LinkList()
	c.Assert(err, IsNil)

	if len(ifaces) == 0 {
		c.Skip("no interfaces to test")
	}

	var (
		iface = ifaces[0]
		mgr   = New(iface.Attrs().Name)
	)

	mgr.AddAddress(nil)
	mgr.RemoveAddress(nil)
}

func ipv6(addr string) addressing.CiliumIPv6 {
	ret, _ := addressing.NewCiliumIPv6(addr)
	return ret
}
