// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/node"
)

// RemoteSNATDstAddrExclusionCIDRv4 returns a CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd.
func RemoteSNATDstAddrExclusionCIDRv4(localNode node.LocalNode) *cidr.CIDR {
	if localNode.Local.IPv4NativeRoutingCIDR != nil {
		// ipv4-native-routing-cidr is set or has been autodetected, so use it
		return localNode.Local.IPv4NativeRoutingCIDR
	}

	return localNode.IPv4AllocCIDR
}

// RemoteSNATDstAddrExclusionCIDRv6 returns a IPv6 CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd.
func RemoteSNATDstAddrExclusionCIDRv6(localNode node.LocalNode) *cidr.CIDR {
	if localNode.Local.IPv6NativeRoutingCIDR != nil {
		// ipv6-native-routing-cidr is set or has been autodetected, so use it
		return localNode.Local.IPv6NativeRoutingCIDR
	}

	return localNode.IPv6AllocCIDR
}
