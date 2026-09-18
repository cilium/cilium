// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

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
			cfg := types.DeviceConfig{InterfaceSysctlIPv4: tc.ipv4, InterfaceSysctlIPv6: tc.ipv6}
			err := validateInterfaceSysctl(cfg)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBuildSysctlSettings(t *testing.T) {
	t.Run("empty config yields nil", func(t *testing.T) {
		require.Nil(t, buildSysctlSettings(types.DeviceConfig{}, "eth0"))
	})

	t.Run("leaves scoped to the live interface name for both families", func(t *testing.T) {
		cfg := types.DeviceConfig{
			InterfaceSysctlIPv4: map[string]string{"arp_filter": "1"},
			InterfaceSysctlIPv6: map[string]string{"disable_ipv6": "0"},
		}
		got := buildSysctlSettings(cfg, "net1")
		require.ElementsMatch(t, []tables.Sysctl{
			{Name: []string{"net", "ipv4", "conf", "net1", "arp_filter"}, Val: "1"},
			{Name: []string{"net", "ipv6", "conf", "net1", "disable_ipv6"}, Val: "0"},
		}, got)
	})

	t.Run("interface name with dots is kept as a single segment", func(t *testing.T) {
		cfg := types.DeviceConfig{
			InterfaceSysctlIPv4: map[string]string{"arp_filter": "1"},
		}
		got := buildSysctlSettings(cfg, "eth0.100")
		require.Equal(t, []tables.Sysctl{
			{Name: []string{"net", "ipv4", "conf", "eth0.100", "arp_filter"}, Val: "1"},
		}, got)
	})
}
