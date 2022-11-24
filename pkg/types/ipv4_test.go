// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"net/netip"
	"testing"

	"gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
)

var testIPv4Address IPv4 = [4]byte{10, 0, 0, 2}

const expectedStr = "10.0.0.2"

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type IPv4Suite struct{}

var _ = check.Suite(&IPv4Suite{})

func (s *IPv4Suite) TestIP(c *check.C) {
	var expectedAddress net.IP
	expectedAddress = []byte{10, 0, 0, 2}
	result := testIPv4Address.IP()

	c.Assert(result, checker.DeepEquals, expectedAddress)
}

func (s *IPv4Suite) TestAddr(c *check.C) {
	expectedAddress := netip.MustParseAddr(expectedStr)
	result := testIPv4Address.Addr()

	c.Assert(result, checker.DeepEquals, expectedAddress)
}

func (s *IPv4Suite) TestString(c *check.C) {
	result := testIPv4Address.String()

	c.Assert(result, check.Equals, expectedStr)
}

func (s *IPv4Suite) TestMarshalText(c *check.C) {
	md, err := testIPv4Address.MarshalText()
	c.Assert(err, check.Equals, nil)
	c.Assert(string(md), check.Equals, expectedStr)
}

func (s *IPv4Suite) TestUnmarshalText(c *check.C) {
	ip4 := IPv4{}
	err := ip4.UnmarshalText([]byte(expectedStr))
	c.Assert(err, check.Equals, nil)
	c.Assert(ip4, check.Equals, testIPv4Address)
	c.Assert(ip4.String(), check.Equals, expectedStr)
}
