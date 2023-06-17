// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/aws/eni/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func (e *ENISuite) TestGetMaximumAllocatableIPv4(c *check.C) {
	n := &Node{}

	// With no k8sObj defined, it should return 0
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 0)

	// With instance-type = m5.large and first-interface-index = 0, we should be able to allocate up to 3x10-3 addresses
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(0))
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 27)

	// With instance-type = m5.large and first-interface-index = 1, we should be able to allocate up to 2x10-2 addresses
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(1))
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 18)

	// With instance-type = m5.large and first-interface-index = 4, we should return 0 as there is only 3 interfaces
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(4))
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 0)

	// With instance-type = foo we should return 0
	n.k8sObj = newCiliumNode("node", withInstanceType("foo"))
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 0)
}

// TestGetUsedIPWithPrefixes tests the logic computing used IPs on a node when prefix delegation is enabled.
func (e *ENISuite) TestGetUsedIPWithPrefixes(c *check.C) {
	cn := newCiliumNode("node1", withInstanceType("m5a.large"))
	n := &Node{k8sObj: cn}
	eniName := "eni-1"
	prefixes := []string{"10.10.128.0/28", "10.10.128.16/28"}
	eniMap := make(map[string]types.ENI)
	eniMap[eniName] = types.ENI{Prefixes: prefixes}
	cn.Status.ENI.ENIs = eniMap

	allocationMap := make(ipamTypes.AllocationMap)
	allocationMap["10.10.128.2"] = ipamTypes.AllocationIP{Resource: eniName}
	allocationMap["10.10.128.18"] = ipamTypes.AllocationIP{Resource: eniName}
	n.k8sObj.Status.IPAM.Used = allocationMap
	c.Assert(n.GetUsedIPWithPrefixes(), check.Equals, 32)
}
