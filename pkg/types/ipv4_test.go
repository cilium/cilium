// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"net/netip"
	"testing"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

var testIPv4Address IPv4 = [4]byte{10, 0, 0, 2}

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
	expectedAddress := netip.MustParseAddr("10.0.0.2")
	result := testIPv4Address.Addr()

	c.Assert(result, checker.DeepEquals, expectedAddress)
}

func (s *IPv4Suite) TestString(c *check.C) {
	expectedStr := "10.0.0.2"
	result := testIPv4Address.String()

	c.Assert(result, check.Equals, expectedStr)
}
