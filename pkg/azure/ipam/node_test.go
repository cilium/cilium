// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package ipam

import (
	"github.com/cilium/cilium/pkg/azure/types"
	"gopkg.in/check.v1"
)

func (e *IPAMSuite) TestGetMaximumAllocatableIPv4(c *check.C) {
	n := &Node{}
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, types.InterfaceAddressLimit)
}
