// Copyright 2020 Authors of Cilium
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

// +build !privileged_tests

package multicast

import (
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/addressing"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type MulticastSuite struct {
	r *rand.Rand
}

var _ = Suite(&MulticastSuite{
	r: rand.New(rand.NewSource(time.Now().Unix())),
})

func (m *MulticastSuite) TestGroupOps(c *C) {
	ifs, err := net.Interfaces()
	c.Assert(err, IsNil)

	if len(ifs) == 0 {
		c.Skip("no interfaces to test")
	}

	ifc := ifs[0]
	maddr := m.randMaddr()

	// Join Group
	err = JoinGroup(ifc.Name, maddr.String())
	c.Assert(err, IsNil)

	// maddr in group
	inGroup, err := IsInGroup(ifc.Name, maddr.String())
	c.Assert(err, IsNil)
	c.Assert(inGroup, Equals, true)

	// LeaveGroup
	err = LeaveGroup(ifc.Name, maddr.String())
	c.Assert(err, IsNil)

	// maddr not in group
	inGroup, err = IsInGroup(ifc.Name, maddr.String())
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
		ip, _ := addressing.NewCiliumIPv6(test.ip)
		got := Address(ip).SolicitedNodeMaddr().String()
		c.Assert(got, Equals, test.expected)
	}

}

func (m *MulticastSuite) randMaddr() addressing.CiliumIPv6 {
	maddr := make([]byte, 16)
	m.r.Read(maddr[13:])
	return Address(maddr).SolicitedNodeMaddr()
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
		ipv6, err := addressing.NewCiliumIPv6(test.ipv6)
		c.Assert(err, IsNil)
		c.Assert(Address(ipv6).Key(), Equals, test.key)
	}
}
