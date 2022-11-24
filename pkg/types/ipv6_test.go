// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"net/netip"

	"gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
)

var testIPv6Address IPv6 = [16]byte{240, 13, 0, 0, 0, 0, 0, 0, 172, 16, 0, 20, 0, 0, 0, 1}

const expectedStr6 = "f00d::ac10:14:0:1"

type IPv6Suite struct{}

var _ = check.Suite(&IPv6Suite{})

func (s *IPv6Suite) TestIP(c *check.C) {
	var expectedAddress net.IP
	expectedAddress = []byte{240, 13, 0, 0, 0, 0, 0, 0, 172, 16, 0, 20, 0, 0, 0, 1}
	result := testIPv6Address.IP()

	c.Assert(result, checker.DeepEquals, expectedAddress)
}

func (s *IPv6Suite) TestAddr(c *check.C) {
	expectedAddress := netip.AddrFrom16(testIPv6Address)
	result := testIPv6Address.Addr()

	c.Assert(result, checker.DeepEquals, expectedAddress)
}

func (s *IPv6Suite) TestString(c *check.C) {
	result := testIPv6Address.String()

	c.Assert(result, check.Equals, expectedStr6)
}

func (s *IPv6Suite) TestMarshalText(c *check.C) {
	md, err := testIPv6Address.MarshalText()
	c.Assert(err, check.Equals, nil)
	c.Assert(string(md), check.Equals, expectedStr6)
}

func (s *IPv6Suite) TestUnmarshalText(c *check.C) {
	ip6 := IPv6{}
	err := ip6.UnmarshalText([]byte(expectedStr6))
	c.Assert(err, check.Equals, nil)
	c.Assert(ip6, check.Equals, testIPv6Address)
	c.Assert(ip6.String(), check.Equals, expectedStr6)
}
