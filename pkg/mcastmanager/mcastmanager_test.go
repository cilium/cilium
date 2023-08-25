// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcastmanager

import (
	"net/netip"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"
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

	mgr := New(ifaces[0].Attrs().Name)

	// Add first endpoint
	mgr.AddAddress(netip.MustParseAddr("f00d::1234"))

	c.Assert(mgr.state, HasLen, 1)
	_, ok := mgr.state[netip.MustParseAddr("ff02::1:ff00:1234")]
	c.Assert(ok, Equals, true)

	// Add another endpoint that shares the same maddr
	mgr.AddAddress(netip.MustParseAddr("f00d:aabb::1234"))

	c.Assert(mgr.state, HasLen, 1)

	// Remove the first endpoint
	mgr.RemoveAddress(netip.MustParseAddr("f00d::1234"))

	c.Assert(mgr.state, HasLen, 1)
	_, ok = mgr.state[netip.MustParseAddr("ff02::1:ff00:1234")]
	c.Assert(ok, Equals, true)

	// Remove the second endpoint
	mgr.RemoveAddress(netip.MustParseAddr("f00d:aabb::1234"))

	c.Assert(mgr.state, HasLen, 0)
	_, ok = mgr.state[netip.MustParseAddr("ff02::1:ff00:1234")]
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

	mgr.AddAddress(netip.Addr{})
	c.Assert(mgr.state, HasLen, 0)
	mgr.RemoveAddress(netip.Addr{})
	c.Assert(mgr.state, HasLen, 0)
}
