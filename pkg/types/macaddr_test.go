// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"

	"gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
)

var testMACAddress MACAddr = [6]byte{1, 2, 3, 4, 5, 6}

const expectedMACStr = "01:02:03:04:05:06"

type MACAddrSuite struct{}

var _ = check.Suite(&MACAddrSuite{})

func (s *MACAddrSuite) TestHardwareAddr(c *check.C) {
	var expectedAddress net.HardwareAddr
	expectedAddress = []byte{1, 2, 3, 4, 5, 6}
	result := testMACAddress.hardwareAddr()

	c.Assert(result, checker.DeepEquals, expectedAddress)
}

func (s *MACAddrSuite) TestString(c *check.C) {
	result := testMACAddress.String()

	c.Assert(result, check.Equals, expectedMACStr)

	md, err := testMACAddress.MarshalText()
	c.Assert(err, check.Equals, nil)
	c.Assert(string(md), check.Equals, expectedMACStr)
}

func (s *MACAddrSuite) TestMarshalText(c *check.C) {
	md, err := testMACAddress.MarshalText()
	c.Assert(err, check.Equals, nil)
	c.Assert(string(md), check.Equals, expectedMACStr)
}

func (s *MACAddrSuite) TestUnmarshalText(c *check.C) {
	mac := &MACAddr{}
	err := mac.UnmarshalText([]byte(expectedMACStr))
	c.Assert(err, check.Equals, nil)
	c.Assert(string(mac.String()), check.Equals, expectedMACStr)
}
