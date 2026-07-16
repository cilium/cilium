// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/cidr"
)

// RemoteSNATDstAddrExclusionCIDRv4 returns a CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd.
func (n *LocalNode) RemoteSNATDstAddrExclusionCIDRv4() *cidr.CIDR {
	if n.Local.IPv4NativeRoutingCIDR != nil {
		// ipv4-native-routing-cidr is set or has been autodetected, so use it
		return n.Local.IPv4NativeRoutingCIDR
	}

	if p := n.IPv4AllocCIDR.Prefix.Prefix; p.IsValid() {
		return cidr.NewCIDR(netipx.PrefixIPNet(p))
	}
	return nil
}

// RemoteSNATDstAddrExclusionCIDRv6 returns a IPv6 CIDR for SNAT exclusion. Any
// packet sent from a local endpoint to an IP address belonging to the CIDR
// should not be SNAT'd.
func (n *LocalNode) RemoteSNATDstAddrExclusionCIDRv6() *cidr.CIDR {
	if n.Local.IPv6NativeRoutingCIDR != nil {
		// ipv6-native-routing-cidr is set or has been autodetected, so use it
		return n.Local.IPv6NativeRoutingCIDR
	}

	if p := n.IPv6AllocCIDR.Prefix.Prefix; p.IsValid() {
		return cidr.NewCIDR(netipx.PrefixIPNet(p))
	}
	return nil
}
