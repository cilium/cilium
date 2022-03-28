// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package ipam

import (
	"gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/azure/types"
)

func (e *IPAMSuite) TestGetMaximumAllocatableIPv4(c *check.C) {
	n := &Node{}
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, types.InterfaceAddressLimit)
}
