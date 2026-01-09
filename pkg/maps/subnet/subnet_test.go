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

func TestKeyString(t *testing.T) {
	tests := []struct {
		name     string
		key      SubnetMapKey
		expected string
	}{
		{
			name: "IPv4 /24",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(24),
				Family:    bpf.EndpointKeyIPv4,
				IP:        types.IPv6{192, 168, 1, 0},
			},
			expected: "192.168.1.0/24",
		},
		{
			name: "IPv4 /32",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(32),
				Family:    bpf.EndpointKeyIPv4,
				IP:        types.IPv6{10, 0, 0, 1},
			},
			expected: "10.0.0.1/32",
		},
		{
			name: "IPv6 /64",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(64),
				Family:    bpf.EndpointKeyIPv6,
				IP:        types.IPv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			expected: "2001:db8::/64",
		},
		{
			name: "IPv6 /128",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(128),
				Family:    bpf.EndpointKeyIPv6,
				IP:        types.IPv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
			expected: "2001:db8::1/128",
		},
		{
			name: "Unknown family",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(24),
				Family:    99,
				IP:        types.IPv6{192, 168, 1, 0},
			},
			expected: "<unknown>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.key.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKeyPrefix(t *testing.T) {
	tests := []struct {
		name     string
		key      SubnetMapKey
		expected netip.Prefix
	}{
		{
			name: "IPv4 /24",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(24),
				Family:    bpf.EndpointKeyIPv4,
				IP:        types.IPv6{192, 168, 1, 0},
			},
			expected: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name: "IPv4 /16",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(16),
				Family:    bpf.EndpointKeyIPv4,
				IP:        types.IPv6{10, 20, 0, 0},
			},
			expected: netip.MustParsePrefix("10.20.0.0/16"),
		},
		{
			name: "IPv6 /64",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(64),
				Family:    bpf.EndpointKeyIPv6,
				IP:        types.IPv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			expected: netip.MustParsePrefix("2001:db8::/64"),
		},
		{
			name: "IPv6 /128",
			key: SubnetMapKey{
				Prefixlen: getPrefixLen(128),
				Family:    bpf.EndpointKeyIPv6,
				IP:        types.IPv6{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
			expected: netip.MustParsePrefix("fd00::1/128"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.key.Prefix()
			assert.Equal(t, tt.expected, result)
		})
	}
}
