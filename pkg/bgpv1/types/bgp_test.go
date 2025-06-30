// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_RoutePolicyConditionsString(t *testing.T) {
	testPrefix, err := netip.ParsePrefix("192.2.0.1/24")
	if err != nil {
		t.Error(err)
	}

	tests := []struct {
		name       string
		conditions RoutePolicyConditions
		expected   string
	}{
		{
			name:       "empty",
			conditions: RoutePolicyConditions{},
			expected:   "",
		},
		{
			name: "sets only neighbors",
			conditions: RoutePolicyConditions{
				MatchNeighbors: []string{"192.2.0.1", "192.2.0.2"},
				MatchPrefixes:  []*RoutePolicyPrefixMatch{},
				MatchFamilies:  []Family{},
			},
			expected: "192.2.0.1-192.2.0.2",
		},
		{
			name: "sets only prefixes",
			conditions: RoutePolicyConditions{
				MatchNeighbors: []string{},
				MatchPrefixes: []*RoutePolicyPrefixMatch{
					{
						CIDR: testPrefix,
					}},
				MatchFamilies: []Family{},
			},
			expected: "192.2.0.1/24",
		},
		{
			name: "sets only families",
			conditions: RoutePolicyConditions{
				MatchNeighbors: []string{},
				MatchPrefixes:  []*RoutePolicyPrefixMatch{},
				MatchFamilies: []Family{
					{
						Afi:  AfiIPv6,
						Safi: SafiUnicast,
					},
				},
			},
			expected: "ipv6-unicast",
		},
		{
			name: "sets families and prefixes",
			conditions: RoutePolicyConditions{
				MatchNeighbors: []string{},
				MatchPrefixes: []*RoutePolicyPrefixMatch{
					{
						CIDR: testPrefix,
					},
				},
				MatchFamilies: []Family{
					{
						Afi:  AfiIPv6,
						Safi: SafiUnicast,
					},
				},
			},
			expected: "ipv6-unicast-192.2.0.1/24",
		},
		{
			name: "sets families prefixes neighbors",
			conditions: RoutePolicyConditions{
				MatchNeighbors: []string{"192.2.0.1", "192.2.0.2"},
				MatchPrefixes: []*RoutePolicyPrefixMatch{
					{
						CIDR: testPrefix,
					},
				},
				MatchFamilies: []Family{
					{
						Afi:  AfiIPv6,
						Safi: SafiUnicast,
					},
				},
			},
			expected: "192.2.0.1-192.2.0.2-ipv6-unicast-192.2.0.1/24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			result := tt.conditions.String()
			req.Equal(tt.expected, result)
		})
	}
}
