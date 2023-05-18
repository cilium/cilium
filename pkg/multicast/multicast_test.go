// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multicast

import (
	"math/rand"
	"net/netip"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"
)

func Test(t *testing.T) { TestingT(t) }

type MulticastSuite struct {
	r *rand.Rand
}

var _ = Suite(&MulticastSuite{
	r: rand.New(rand.NewSource(time.Now().Unix())),
})

func (m *MulticastSuite) TestGroupOps(c *C) {
	ifs, err := netlink.LinkList()
	c.Assert(err, IsNil)

	if len(ifs) == 0 {
		c.Skip("no interfaces to test")
	}

	ifc := ifs[0]
	maddr := m.randMaddr()

	// Join Group
	err = JoinGroup(ifc.Attrs().Name, maddr)
	c.Assert(err, IsNil)

	// maddr in group
	inGroup, err := IsInGroup(ifc.Attrs().Name, maddr)
	c.Assert(err, IsNil)
	c.Assert(inGroup, Equals, true)

	// LeaveGroup
	err = LeaveGroup(ifc.Attrs().Name, maddr)
	c.Assert(err, IsNil)

	// maddr not in group
	inGroup, err = IsInGroup(ifc.Attrs().Name, maddr)
	c.Assert(err, IsNil)
	c.Assert(inGroup, Equals, false)
}

func (m *MulticastSuite) TestSolicitedNodeMaddr(c *C) {
	tests := []struct {
		ip       string
		expected string
	}{
		{
			ip:       "f00d:abcd:ef01::abcd",
			expected: "ff02::1:ff00:abcd",
		},
	}

	for _, test := range tests {
		ip := netip.MustParseAddr(test.ip)
		got := Address(ip).SolicitedNodeMaddr().String()
		c.Assert(got, Equals, test.expected)
	}

}

func (m *MulticastSuite) randMaddr() netip.Addr {
	maddr := make([]byte, 16)
	m.r.Read(maddr[13:])
	return Address(netip.AddrFrom16(*(*[16]byte)(maddr))).SolicitedNodeMaddr()
}

func (m *MulticastSuite) TestMcastKey(c *C) {
	tests := []struct {
		ipv6 string
		key  int32
	}{
		{
			ipv6: "f00d::",
			key:  0x0,
		},
		{
			ipv6: "f00d::1000",
			key:  0x1000,
		},
		{
			ipv6: "f00d::11:1000",
			key:  0x111000,
		},
		{
			ipv6: "f00d::aa:aaaa",
			key:  0xaaaaaa,
		},
		{
			ipv6: "f00d::ff:ffff",
			key:  0xffffff,
		},
		{
			ipv6: "f00d::11ff:ffff",
			key:  0xffffff,
		},
	}

	for _, test := range tests {
		ipv6 := netip.MustParseAddr(test.ipv6)
		c.Assert(Address(ipv6).Key(), Equals, test.key)
	}
}
