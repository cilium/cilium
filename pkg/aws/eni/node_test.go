// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	n := &Node{}

	// With no k8sObj defined, it should return 0
	require.Equal(t, 0, n.GetMaximumAllocatableIP(ipam.IPv4))

	// With instance-type = m5.large and first-interface-index = 0, we should be able to allocate up to 3x10-3 addresses
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(0))
	require.Equal(t, 27, n.GetMaximumAllocatableIP(ipam.IPv4))

	// With instance-type = m5.large and first-interface-index = 1, we should be able to allocate up to 2x10-2 addresses
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(1))
	require.Equal(t, 18, n.GetMaximumAllocatableIP(ipam.IPv4))

	// With instance-type = m5.large and first-interface-index = 4, we should return 0 as there is only 3 interfaces
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(4))
	require.Equal(t, 0, n.GetMaximumAllocatableIP(ipam.IPv4))

	// With instance-type = foo we should return 0
	n.k8sObj = newCiliumNode("node", withInstanceType("foo"))
	require.Equal(t, 0, n.GetMaximumAllocatableIP(ipam.IPv4))
}

func TestGetMaximumAllocatableIPv6(t *testing.T) {
	n := &Node{}

	// With no k8sObj defined, it should return 64
	require.Equal(t, 0, n.GetMaximumAllocatableIP(ipam.IPv6))

	// With instance-type = m5.large and first-interface-index = 0, we should be able to allocate up to
	// ((10-1 prefix allocations) * 64 ENIPDBlockSizeIPv6) * 3 ENIs.
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(0))
	require.Equal(t, 1728, n.GetMaximumAllocatableIP(ipam.IPv6))

	// With instance-type = m5.large and first-interface-index = 1, we should be able to allocate up to
	// ((10-1 prefix allocations) * 64 ENIPDBlockSizeIPv6) * 2 ENIs.
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(1))
	require.Equal(t, 1152, n.GetMaximumAllocatableIP(ipam.IPv6))

	// With instance-type = m5.large and first-interface-index = 4, we should return 0 as there is only 3 interfaces
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(4))
	require.Equal(t, 0, n.GetMaximumAllocatableIP(ipam.IPv6))

	// With instance-type = foo we should return 0
	n.k8sObj = newCiliumNode("node", withInstanceType("foo"))
	require.Equal(t, 0, n.GetMaximumAllocatableIP(ipam.IPv6))
}

// TestGetUsedIPWithPrefixes tests the logic computing used IPs on a node when prefix delegation is enabled.
func TestGetUsedIPWithPrefixes(t *testing.T) {
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
	require.Equal(t, 32, n.GetUsedIPWithPrefixes(ipam.IPv4))
}

// TestGetUsedIPWithPrefixes tests the logic computing used IPv6 addresses
// on a node when prefix delegation is enabled.
func TestGetUsedIPv6WithPrefixes(t *testing.T) {
	cn := newCiliumNode("node1", withInstanceType("m5a.large"))
	n := &Node{k8sObj: cn}
	eniName := "eni-1"
	prefixes := []string{"2001:db8::/80", "2001:db8:1::/80"}
	eniMap := make(map[string]types.ENI)
	eniMap[eniName] = types.ENI{IPv6Prefixes: prefixes}
	cn.Status.ENI.ENIs = eniMap

	allocationMap := make(ipamTypes.AllocationMap)
	allocationMap["2001:db8::1"] = ipamTypes.AllocationIP{Resource: eniName}
	allocationMap["2001:db8:1::1"] = ipamTypes.AllocationIP{Resource: eniName}
	n.k8sObj.Status.IPAM.IPv6Used = allocationMap
	require.Equal(t, 128, n.GetUsedIPWithPrefixes(ipam.IPv6)) // 64 IPs per prefix
}
