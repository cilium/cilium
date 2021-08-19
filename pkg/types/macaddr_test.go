// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package types

import (
	"net"

	"github.com/cilium/cilium/pkg/checker"

	"gopkg.in/check.v1"
)

var testMACAddress MACAddr = [6]byte{1, 2, 3, 4, 5, 6}

type MACAddrSuite struct{}

var _ = check.Suite(&MACAddrSuite{})

func (s *MACAddrSuite) TestHardwareAddr(c *check.C) {
	var expectedAddress net.HardwareAddr
	expectedAddress = []byte{1, 2, 3, 4, 5, 6}
	result := testMACAddress.hardwareAddr()

	c.Assert(result, checker.DeepEquals, expectedAddress)
}

func (s *MACAddrSuite) TestString(c *check.C) {
	expectedStr := "01:02:03:04:05:06"
	result := testMACAddress.String()

	c.Assert(result, check.Equals, expectedStr)
}
