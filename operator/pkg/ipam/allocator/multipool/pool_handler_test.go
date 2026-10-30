// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"go4.org/netipx"

	iputil "github.com/cilium/cilium/pkg/ip"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func addr(s string) iputil.Addr {
	return iputil.AddrFrom(netip.MustParseAddr(s))
}

func TestBuildReservedRanges(t *testing.T) {
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
				{Start: addr("10.0.0.10"), End: addr("10.0.0.20")},
			},
			expected: []netipx.IPRange{
				netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("10.0.0.20")),
			},
		},
		{
			name:     "valid IPv6 range",
			poolCIDR: netip.MustParsePrefix("fd00:100::/80"),
			ranges: []v2.ReservedRange{
				{Start: addr("fd00:100::10"), End: addr("fd00:100::20")},
			},
			expected: []netipx.IPRange{
				netipx.IPRangeFrom(netip.MustParseAddr("fd00:100::10"), netip.MustParseAddr("fd00:100::20")),
			},
		},
		{
			name:     "single-address range (start == end)",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: addr("10.0.0.5"), End: addr("10.0.0.5")},
			},
			expected: []netipx.IPRange{
				netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.5")),
			},
		},
		{
			name:     "multiple ranges",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: addr("10.0.0.10"), End: addr("10.0.0.20")},
				{Start: addr("10.0.1.0"), End: addr("10.0.1.5")},
			},
			expected: []netipx.IPRange{
				netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("10.0.0.20")),
				netipx.IPRangeFrom(netip.MustParseAddr("10.0.1.0"), netip.MustParseAddr("10.0.1.5")),
			},
		},
		{
			name:     "mixed address families",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: addr("10.0.0.10"), End: addr("fd00::20")},
			},
			errMatch: "invalid reserved range 10.0.0.10-fd00::20",
		},
		{
			name:     "start greater than end",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: addr("10.0.0.40"), End: addr("10.0.0.10")},
			},
			errMatch: "invalid reserved range 10.0.0.40-10.0.0.10",
		},
		{
			name:     "range outside pool CIDR",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/16"),
			ranges: []v2.ReservedRange{
				{Start: addr("10.1.0.10"), End: addr("10.1.0.20")},
			},
			errMatch: "is outside pool CIDR 10.0.0.0/16",
		},
		{
			name:     "range partially outside pool CIDR",
			poolCIDR: netip.MustParsePrefix("10.0.0.0/24"),
			ranges: []v2.ReservedRange{
				{Start: addr("10.0.0.250"), End: addr("10.0.1.10")},
			},
			errMatch: "is outside pool CIDR 10.0.0.0/24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := buildReservedRanges(tt.poolCIDR, tt.ranges)
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
