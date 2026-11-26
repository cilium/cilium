// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkconfig

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLongestPrefixSpecMatch(t *testing.T) {
	cfg := LocalResourceNetworkConfig{
		Name: "cfg",
		Spec: networkConfigSpec{
			IPv4: []IPSpec{
				{CIDR: netip.MustParsePrefix("10.0.0.0/8")},
				{CIDR: netip.MustParsePrefix("10.20.0.0/16")},
				{CIDR: netip.MustParsePrefix("10.20.1.0/24")},
			},
			IPv6: []IPSpec{
				{CIDR: netip.MustParsePrefix("fd00::/16")},
				{CIDR: netip.MustParsePrefix("fd00:20::/48")},
			},
		},
	}
	ipv4Only := LocalResourceNetworkConfig{Spec: networkConfigSpec{IPv4: cfg.Spec.IPv4}}
	ipv6Only := LocalResourceNetworkConfig{Spec: networkConfigSpec{IPv6: cfg.Spec.IPv6}}

	tests := []struct {
		name     string
		cfg      LocalResourceNetworkConfig
		addr     netip.Addr
		wantCIDR string
	}{
		{"ipv4, most specific entry", cfg, netip.MustParseAddr("10.20.1.5"), "10.20.1.0/24"},
		{"ipv4, less specific entry", cfg, netip.MustParseAddr("10.20.2.5"), "10.20.0.0/16"},
		{"ipv4, least specific entry", cfg, netip.MustParseAddr("10.99.0.1"), "10.0.0.0/8"},
		{"ipv4, no matching entry", cfg, netip.MustParseAddr("192.168.0.1"), ""},
		{"ipv6, most specific entry", cfg, netip.MustParseAddr("fd00:20::5"), "fd00:20::/48"},
		{"ipv6, less specific entry", cfg, netip.MustParseAddr("fd00:30::5"), "fd00::/16"},
		{"ipv6, no matching entry", cfg, netip.MustParseAddr("fe80::1"), ""},
		{"ipv4 address, only ipv6 entries", ipv6Only, netip.MustParseAddr("10.20.1.5"), ""},
		{"ipv6 address, only ipv4 entries", ipv4Only, netip.MustParseAddr("fd00:20::5"), ""},
		{"invalid address", cfg, netip.Addr{}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, found := tc.cfg.LongestPrefixSpecMatch(tc.addr)
			if tc.wantCIDR == "" {
				assert.False(t, found)
				return
			}
			assert.True(t, found)
			assert.Equal(t, netip.MustParsePrefix(tc.wantCIDR), spec.CIDR)
		})
	}
}

func TestGetPrefixLength(t *testing.T) {
	tests := []struct {
		name string
		spec IPSpec
		want int
	}{
		{
			name: "explicit prefix length",
			spec: IPSpec{CIDR: netip.MustParsePrefix("10.20.0.0/16"), PrefixLength: new(20)},
			want: 20,
		},
		{
			name: "explicit prefix length shorter than the CIDR",
			spec: IPSpec{CIDR: netip.MustParsePrefix("10.20.0.0/16"), PrefixLength: new(8)},
			want: 8,
		},
		{
			name: "no prefix length: CIDR length",
			spec: IPSpec{CIDR: netip.MustParsePrefix("10.20.0.0/16")},
			want: 16,
		},
		{
			name: "no prefix length, ipv6: CIDR length",
			spec: IPSpec{CIDR: netip.MustParsePrefix("fd00:20::/48")},
			want: 48,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.spec.GetPrefixLength())
		})
	}
}
