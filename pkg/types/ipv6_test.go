// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"net/netip"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

var testIPv6Address IPv6 = [16]byte{240, 13, 0, 0, 0, 0, 0, 0, 172, 16, 0, 20, 0, 0, 0, 1}

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
	expectedStr := "f00d::ac10:14:0:1"
	result := testIPv6Address.String()

	c.Assert(result, check.Equals, expectedStr)
}
