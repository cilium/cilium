// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

func TestKey(t *testing.T) {
	tests := []struct {
		name           string
		key            SubnetMapKey
		expectedString string
		expectedPrefix netip.Prefix
	}{
		{
			name: "IPv4 /24",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(24),
				Family:    bpf.EndpointKeyIPv4,
				IP:        types.IPv6{192, 168, 1, 0},
			},
			expectedString: "192.168.1.0/24",
			expectedPrefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name: "IPv4 /32",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(32),
				Family:    bpf.EndpointKeyIPv4,
				IP:        types.IPv6{10, 0, 0, 1},
			},
			expectedString: "10.0.0.1/32",
			expectedPrefix: netip.MustParsePrefix("10.0.0.1/32"),
		},
		{
			name: "IPv4 /16",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(16),
				Family:    bpf.EndpointKeyIPv4,
				IP:        types.IPv6{10, 20, 0, 0},
			},
			expectedString: "10.20.0.0/16",
			expectedPrefix: netip.MustParsePrefix("10.20.0.0/16"),
		},
		{
			name: "IPv6 /64",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(64),
				Family:    bpf.EndpointKeyIPv6,
				IP:        types.IPv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			expectedString: "2001:db8::/64",
			expectedPrefix: netip.MustParsePrefix("2001:db8::/64"),
		},
		{
			name: "IPv6 /128",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(128),
				Family:    bpf.EndpointKeyIPv6,
				IP:        types.IPv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
			expectedString: "2001:db8::1/128",
			expectedPrefix: netip.MustParsePrefix("2001:db8::1/128"),
		},
		{
			name: "Unknown family",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(24),
				Family:    99,
				IP:        types.IPv6{192, 168, 1, 0},
			},
			expectedString: "<unknown>",
			expectedPrefix: netip.Prefix{}, // zero value for unknown family
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedString, tt.key.String())
			assert.Equal(t, tt.expectedPrefix, tt.key.Prefix())
		})
	}
}
