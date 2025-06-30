// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"
	"slices"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

// CanAdvertisePodCIDR returns true if the provided IPAM mode is supported for
// advertising PodCIDR
func CanAdvertisePodCIDR(ipam string) bool {
	supportedIPAMs := []string{
		ipamOption.IPAMKubernetes,
		ipamOption.IPAMClusterPool,
	}
	return slices.Contains(supportedIPAMs, ipam)
}

// NewPathForPrefix returns a Path that can be used to advertise the provided
// IP prefix by the underlying BGP implementation.
//
// The prefix can be either IPv4 or IPv6 and this function will handle the differences
// between MP BGP and BGP.
//
// The next hop of the path will always be set to "0.0.0.0" for IPv4 and "::" for IPv6,
// so the underlying BGP implementation selects appropriate actual nexthop address when advertising it.
func NewPathForPrefix(prefix netip.Prefix) (path *Path) {
	originAttr := bgp.NewPathAttributeOrigin(0)

	// Currently, we only support advertising locally originated paths (the paths generated in Cilium
	// node itself, not the paths received from another BGP Peer or redistributed from another routing
	// protocol. In this case, the nexthop address should be the address used for peering. That means
	// the nexthop address can be changed depending on the neighbor.
	//
	// For example, when the Cilium node is connected to two subnets 10.0.0.0/24 and 10.0.1.0/24 with
	// local address 10.0.0.1 and 10.0.1.1 respectively, the nexthop should be advertised for 10.0.0.0/24
	// peers is 10.0.0.1. On the other hand, we should advertise 10.0.1.1 as a nexthop for 10.0.1.0/24.
	//
	// Fortunately, GoBGP takes care of resolving appropriate nexthop address for each peers when we
	// specify an zero IP address (0.0.0.0 for IPv4 and :: for IPv6). So, we can just rely on that.
	//
	// References:
	// - RFC4271 Section 5.1.3 (NEXT_HOP)
	// - RFC4760 Section 3 (Multiprotocol Reachable NLRI - MP_REACH_NLRI (Type Code 14))

	switch {
	case prefix.Addr().Is4():
		nlri := bgp.NewIPAddrPrefix(uint8(prefix.Bits()), prefix.Addr().String())
		nextHopAttr := bgp.NewPathAttributeNextHop("0.0.0.0")
		path = &Path{
			NLRI: nlri,
			PathAttributes: []bgp.PathAttributeInterface{
				originAttr,
				nextHopAttr,
			},
		}
	case prefix.Addr().Is6():
		nlri := bgp.NewIPv6AddrPrefix(uint8(prefix.Bits()), prefix.Addr().String())
		mpReachNLRIAttr := bgp.NewPathAttributeMpReachNLRI("::", []bgp.AddrPrefixInterface{nlri})
		path = &Path{
			NLRI: nlri,
			PathAttributes: []bgp.PathAttributeInterface{
				originAttr,
				mpReachNLRIAttr,
			},
		}
	}

	return
}

// DeepEqual is a manually created deepequal function, deeply comparing the receiver with another.
// It compares fields with types that do not implement the `DeepEqual` method
// and calls the generated private `deepEqual` method which compares the rest of the fields.
func (m *RoutePolicyPrefixMatch) DeepEqual(other *RoutePolicyPrefixMatch) bool {
	// Compare netip.Prefix field (does not implement the `DeepEqual` method)
	if m.CIDR != other.CIDR {
		return false
	}
	// Call generated `deepEqual` method which compares all fields except 'CIDR'
	return m.deepEqual(other)
}

type PolicyPrefixMatchList []*RoutePolicyPrefixMatch

// Less is a comparator of two RoutePolicyPrefixMatch rules to be used for sorting purposes
func (l PolicyPrefixMatchList) Less(i, j int) bool {
	return l[i].CIDR.Bits() < l[j].CIDR.Bits() || l[i].CIDR.Addr().Less(l[j].CIDR.Addr()) ||
		l[i].PrefixLenMin < l[j].PrefixLenMin || l[i].PrefixLenMax < l[j].PrefixLenMax
}
