// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

// +build !privileged_tests

package types

import (
	"net"

	"github.com/cilium/cilium/pkg/checker"

	"gopkg.in/check.v1"
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

func (s *IPv6Suite) TestString(c *check.C) {
	expectedStr := "f00d::ac10:14:0:1"
	result := testIPv6Address.String()

	c.Assert(result, check.Equals, expectedStr)
}
