// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"net/netip"

	"go4.org/netipx"
)

// RemoteSNATDstAddrExclusionCIDRv4 returns a CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd. The zero Prefix is returned if no CIDR is known.
func (n *LocalNode) RemoteSNATDstAddrExclusionCIDRv4() netip.Prefix {
	if n.Local.IPv4NativeRoutingCIDR != nil {
		// ipv4-native-routing-cidr is set or has been autodetected, so use it
		if p, ok := netipx.FromStdIPNet(n.Local.IPv4NativeRoutingCIDR.IPNet); ok && p.IsValid() {
			return p
		}
		return netip.Prefix{}
	}

	return n.IPv4AllocCIDR.Prefix.Prefix
}

// RemoteSNATDstAddrExclusionCIDRv6 returns a IPv6 CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd. The zero Prefix is returned if no CIDR is known.
func (n *LocalNode) RemoteSNATDstAddrExclusionCIDRv6() netip.Prefix {
	if n.Local.IPv6NativeRoutingCIDR != nil {
		// ipv6-native-routing-cidr is set or has been autodetected, so use it
		if p, ok := netipx.FromStdIPNet(n.Local.IPv6NativeRoutingCIDR.IPNet); ok && p.IsValid() {
			return p
		}
		return netip.Prefix{}
	}

	return n.IPv6AllocCIDR.Prefix.Prefix
}
