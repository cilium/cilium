// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"k8s.io/utils/ptr"
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

	// TestCommonRoutePolicies contains common route policy values to be used in tests
	TestCommonRoutePolicies = []struct {
		Name   string
		Policy *RoutePolicy
		Valid  bool
	}{
		{
			Name: "simple policy",
			Policy: &RoutePolicy{
				Name: "testpolicy1",
				Type: RoutePolicyTypeExport,
				Statements: []*RoutePolicyStatement{
					{
						Conditions: RoutePolicyConditions{
							MatchNeighbors: []string{"172.16.0.1/32"},
							MatchPrefixes: []*RoutePolicyPrefixMatch{
								{
									CIDR:         netip.MustParsePrefix("1.2.3.0/24"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
							},
						},
						Actions: RoutePolicyActions{
							RouteAction:         RoutePolicyActionNone,
							AddCommunities:      []string{"65000:100"},
							AddLargeCommunities: []string{"4294967295:0:100"},
							SetLocalPreference:  ptr.To[int64](150),
						},
					},
				},
			},
			Valid: true,
		},
		{
			Name: "complex policy",
			Policy: &RoutePolicy{
				Name: "testpolicy1",
				Type: RoutePolicyTypeExport,
				Statements: []*RoutePolicyStatement{
					{
						Conditions: RoutePolicyConditions{
							MatchNeighbors: []string{"172.16.0.1/32", "10.10.10.10/32"},
							MatchPrefixes: []*RoutePolicyPrefixMatch{
								{
									CIDR:         netip.MustParsePrefix("1.2.3.0/24"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
								{
									CIDR:         netip.MustParsePrefix("192.188.0.0/16"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
							},
						},
						Actions: RoutePolicyActions{
							RouteAction:        RoutePolicyActionNone,
							AddCommunities:     []string{"65000:100", "65000:101"},
							SetLocalPreference: ptr.To[int64](150),
						},
					},
					{
						Conditions: RoutePolicyConditions{
							MatchNeighbors: []string{"fe80::210:5aff:feaa:20a2/128"},
							MatchPrefixes: []*RoutePolicyPrefixMatch{
								{
									CIDR:         netip.MustParsePrefix("2001:0DB8::/64"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
								{
									CIDR:         netip.MustParsePrefix("2002::/16"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
							},
						},
						Actions: RoutePolicyActions{
							RouteAction:        RoutePolicyActionNone,
							AddCommunities:     []string{"65000:100", "65000:101"},
							SetLocalPreference: ptr.To[int64](150),
						},
					},
				},
			},
			Valid: true,
		},
		{
			Name: "invalid policy",
			Policy: &RoutePolicy{
				Name: "testpolicy1",
				Type: RoutePolicyTypeExport,
				Statements: []*RoutePolicyStatement{
					// valid statement
					{
						Conditions: RoutePolicyConditions{
							MatchNeighbors: []string{"172.16.0.1/32"},
							MatchPrefixes: []*RoutePolicyPrefixMatch{
								{
									CIDR:         netip.MustParsePrefix("1.2.3.0/24"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
							},
						},
						Actions: RoutePolicyActions{
							RouteAction:        RoutePolicyActionNone,
							AddCommunities:     []string{"65000:100"},
							SetLocalPreference: ptr.To[int64](150),
						},
					},
					// invalid statement - wrong neighbor address
					{
						Conditions: RoutePolicyConditions{
							MatchNeighbors: []string{"ABCD"},
							MatchPrefixes: []*RoutePolicyPrefixMatch{
								{
									CIDR:         netip.MustParsePrefix("192.188.0.0/16"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
							},
						},
						Actions: RoutePolicyActions{
							RouteAction: RoutePolicyActionNone,
						},
					},
				},
			},
			Valid: false,
		},
	}
)
