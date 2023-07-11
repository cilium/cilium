// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

var (
	prefixV4             = bgp.NewIPAddrPrefix(24, "10.0.0.0")
	prefixV6             = bgp.NewIPv6AddrPrefix(64, "fd00::")
	originAttribute      = bgp.NewPathAttributeOrigin(0)
	nextHopAttribute     = bgp.NewPathAttributeNextHop("0.0.0.0")
	mpReachNLRIAttribute = bgp.NewPathAttributeMpReachNLRI("::", []bgp.AddrPrefixInterface{prefixV6})

	// CommonPaths contains common path structure values appearing in the agent code
	CommonPaths = []struct {
		Name string
		Path Path
	}{
		{
			Name: "IPv4 unicast advertisement",
			Path: Path{
				NLRI: prefixV4,
				PathAttributes: []bgp.PathAttributeInterface{
					originAttribute,
					nextHopAttribute,
				},
			},
		},
		{
			Name: "IPv6 unicast advertisement",
			Path: Path{
				NLRI: prefixV6,
				PathAttributes: []bgp.PathAttributeInterface{
					originAttribute,
					mpReachNLRIAttribute,
				},
			},
		},
	}
)
