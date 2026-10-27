// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateAddressAllocation(t *testing.T) {
	tests := []struct {
		name    string
		config  DeviceConfig
		wantErr bool
	}{
		{
			name: "empty configuration",
		},
		{
			name:   "dynamic pool",
			config: DeviceConfig{IPPool: "pool-a"},
		},
		{
			name: "dual-stack static addresses",
			config: DeviceConfig{
				IPv4Addr: netip.MustParsePrefix("10.0.0.1/32"),
				IPv6Addr: netip.MustParsePrefix("fd00::1/128"),
			},
		},
		{
			name: "pool with static addresses",
			config: DeviceConfig{
				IPPool:   "pool-a",
				IPv4Addr: netip.MustParsePrefix("10.0.0.1/32"),
			},
			wantErr: true,
		},
		{
			name: "invalid static IPv4 prefix",
			config: DeviceConfig{
				IPv4Addr: netip.PrefixFrom(netip.MustParseAddr("10.0.0.1"), 64),
			},
			wantErr: true,
		},
		{
			name: "invalid static IPv6 prefix",
			config: DeviceConfig{
				IPv6Addr: netip.PrefixFrom(netip.MustParseAddr("fd00::1"), 129),
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.validateAddressAllocation()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateInterfaceSysctl(t *testing.T) {
	tests := []struct {
		name    string
		ipv4    map[string]string
		ipv6    map[string]string
		wantErr bool
	}{
		{
			name: "empty",
		},
		{
			name: "valid leaves both families",
			ipv4: map[string]string{"arp_filter": "1"},
			ipv6: map[string]string{"disable_ipv6": "0"},
		},
		{
			name:    "invalid ipv4 leaf character",
			ipv4:    map[string]string{"arp filter": "1"},
			wantErr: true,
		},
		{
			name:    "invalid ipv6 leaf character",
			ipv6:    map[string]string{"disable ipv6": "0"},
			wantErr: true,
		},
		{
			name:    "empty ipv4 value",
			ipv4:    map[string]string{"arp_filter": ""},
			wantErr: true,
		},
		{
			name:    "empty ipv6 value",
			ipv6:    map[string]string{"disable_ipv6": ""},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DeviceConfig{InterfaceSysctlIPv4: tc.ipv4, InterfaceSysctlIPv6: tc.ipv6}
			err := cfg.validateInterfaceSysctl()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
