// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/cilium/cilium/pkg/bgpv1/types"
)

var (
	prefixV4             = bgp.NewIPAddrPrefix(24, "10.0.0.0")
	prefixV6             = bgp.NewIPv6AddrPrefix(64, "fd00::")
	originAttribute      = bgp.NewPathAttributeOrigin(0)
	nextHopAttribute     = bgp.NewPathAttributeNextHop("0.0.0.0")
	mpReachNLRIAttribute = bgp.NewPathAttributeMpReachNLRI("::", []bgp.AddrPrefixInterface{prefixV6})

	// common path structure appearing in the agent code
	commonPaths = []struct {
		name string
		path types.Path
	}{
		{
			name: "IPv4 unicast advertisement",
			path: types.Path{
				NLRI: prefixV4,
				PathAttributes: []bgp.PathAttributeInterface{
					originAttribute,
					nextHopAttribute,
				},
			},
		},
		{
			name: "IPv6 unicast advertisement",
			path: types.Path{
				NLRI: prefixV6,
				PathAttributes: []bgp.PathAttributeInterface{
					originAttribute,
					mpReachNLRIAttribute,
				},
			},
		},
	}
)
