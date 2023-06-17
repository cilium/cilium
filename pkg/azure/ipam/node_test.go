// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/azure/types"
)

func (e *IPAMSuite) TestGetMaximumAllocatableIPv4(c *check.C) {
	n := &Node{}
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, types.InterfaceAddressLimit)
}
