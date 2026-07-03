// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"go4.org/netipx"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestParseReservedRanges(t *testing.T) {
	tests := []struct {
		name     string
		poolCIDR netip.Prefix
		ranges   []v2.ReservedRange
		expected []netipx.IPRange
		errMatch string
	}{
		{
			name:     "no ranges",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges:   nil,
			expected: []netipx.IPRange{},
		},
		{
			name:     "valid IPv4 range",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: "10.0.0.10", End: "10.0.0.20"},
			},
			expected: []netipx.IPRange{
				netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("10.0.0.20")),
			},
		},
		{
			name:     "valid IPv6 range",
			poolCIDR: netip.MustParsePrefix("fd00:100::/80"),
			ranges: []v2.ReservedRange{
				{Start: "fd00:100::10", End: "fd00:100::20"},
			},
			expected: []netipx.IPRange{
				netipx.IPRangeFrom(netip.MustParseAddr("fd00:100::10"), netip.MustParseAddr("fd00:100::20")),
			},
		},
		{
			name:     "single-address range (start == end)",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: "10.0.0.5", End: "10.0.0.5"},
			},
			expected: []netipx.IPRange{
				netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.5")),
			},
		},
		{
			name:     "multiple ranges",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: "10.0.0.10", End: "10.0.0.20"},
				{Start: "10.0.1.0", End: "10.0.1.5"},
			},
			expected: []netipx.IPRange{
				netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("10.0.0.20")),
				netipx.IPRangeFrom(netip.MustParseAddr("10.0.1.0"), netip.MustParseAddr("10.0.1.5")),
			},
		},
		{
			name:     "invalid start IP",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: "not-an-ip", End: "10.0.0.20"},
			},
			errMatch: `invalid reserved range start "not-an-ip"`,
		},
		{
			name:     "invalid end IP",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: "10.0.0.10", End: "10.0.0.999"},
			},
			errMatch: `invalid reserved range end "10.0.0.999"`,
		},
		{
			name:     "start greater than end",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: "10.0.0.40", End: "10.0.0.10"},
			},
			errMatch: "invalid reserved range 10.0.0.40-10.0.0.10",
		},
		{
			name:     "range outside pool CIDR",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: "10.1.0.10", End: "10.1.0.20"},
			},
			errMatch: "is outside pool CIDR 10.0.0.0/16",
		},
		{
			name:     "range partially outside pool CIDR",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/24"),
			ranges: []v2.ReservedRange{
				{Start: "10.0.0.250", End: "10.0.1.10"},
			},
			errMatch: "is outside pool CIDR 10.0.0.0/24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := parseReservedRanges(tt.poolCIDR, tt.ranges)
			if tt.errMatch != "" {
				assert.ErrorContains(t, err, tt.errMatch)
				assert.Nil(t, actual)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
