// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import "github.com/cilium/cilium/pkg/cidr"

// RemoteSNATDstAddrExclusionCIDRv4 returns a CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd.
func (n *LocalNode) RemoteSNATDstAddrExclusionCIDRv4() *cidr.CIDR {
	if n.Local.IPv4NativeRoutingCIDR != nil {
		// ipv4-native-routing-cidr is set or has been autodetected, so use it
		return n.Local.IPv4NativeRoutingCIDR
	}

	return n.IPv4AllocCIDR
}

// RemoteSNATDstAddrExclusionCIDRv6 returns a IPv6 CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd.
func (n *LocalNode) RemoteSNATDstAddrExclusionCIDRv6() *cidr.CIDR {
	if n.Local.IPv6NativeRoutingCIDR != nil {
		// ipv6-native-routing-cidr is set or has been autodetected, so use it
		return n.Local.IPv6NativeRoutingCIDR
	}

	return n.IPv6AllocCIDR
}
