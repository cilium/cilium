// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package ipmasq

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/types"
)

func TestKeyIP(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   netip.Prefix
		want Key4
	}{
		{"ipv4 /32", netip.MustParsePrefix("100.16.3.1/32"), Key4{32, types.IPv4{100, 16, 3, 1}}},
		{"ipv4 /16", netip.MustParsePrefix("100.16.0.0/16"), Key4{16, types.IPv4{100, 16, 0, 0}}},
		{"ipv4 zero masked bits /1", netip.MustParsePrefix("255.16.3.1/1"), Key4{1, types.IPv4{0x80, 0, 0, 0}}},
		{"ipv4 zero masked bits /16", netip.MustParsePrefix("100.16.255.255/16"), Key4{16, types.IPv4{100, 16, 0, 0}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := keyIPv4(tc.in)
			assert.Equal(t, tc.want, *got)
		})
	}
	for _, tc := range []struct {
		name string
		in   netip.Prefix
		want Key6
	}{
		{
			"ipv6 /96",
			netip.MustParsePrefix("10:11:12::/96"),
			Key6{96, types.IPv6{0, 0x10, 0, 0x11, 0, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		},
		{
			"ipv6 zero masked bits /1",
			netip.MustParsePrefix("ffff:2:3:4:5:6:7:8/1"), Key6{1,
				types.IPv6{0x80, 0, 0, 0, 0, 0, 0, 0}},
		},
		{
			"ipv6 zero masked bits /64",
			netip.MustParsePrefix("1:2:3:4:5:6:7:8/64"),
			Key6{64, types.IPv6{0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := keyIPv6(tc.in)
			assert.Equal(t, tc.want, *got)
		})
	}
}
