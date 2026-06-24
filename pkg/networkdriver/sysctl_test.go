// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

func TestValidateSysctl(t *testing.T) {
	tests := []struct {
		name    string
		global  map[string]string
		ifv4    map[string]string
		ifv6    map[string]string
		wantErr bool
	}{
		{
			name: "empty",
		},
		{
			name:   "global non-interface keys ok",
			global: map[string]string{"net.core.somaxconn": "500"},
		},
		{
			name:   "global all pseudo-interface ok",
			global: map[string]string{"net.ipv4.conf.all.rp_filter": "0"},
		},
		{
			name:   "global default pseudo-interface ok",
			global: map[string]string{"net.ipv6.conf.default.disable_ipv6": "1"},
		},
		{
			name:   "global neigh all pseudo-interface ok",
			global: map[string]string{"net.ipv4.neigh.default.gc_stale_time": "60"},
		},
		{
			name:    "global key naming a specific interface rejected",
			global:  map[string]string{"net.ipv4.conf.eth0.arp_filter": "1"},
			wantErr: true,
		},
		{
			name:    "global neigh key naming a specific interface rejected",
			global:  map[string]string{"net.ipv6.neigh.eth0.base_reachable_time_ms": "30000"},
			wantErr: true,
		},
		{
			name:    "global empty value rejected",
			global:  map[string]string{"net.core.somaxconn": ""},
			wantErr: true,
		},
		{
			name:    "global invalid segment rejected",
			global:  map[string]string{"net.core.some$conn": "1"},
			wantErr: true,
		},
		{
			name: "interface leaf keys ok",
			ifv4: map[string]string{"arp_filter": "1"},
			ifv6: map[string]string{"disable_ipv6": "0"},
		},
		{
			name:    "interface empty value rejected",
			ifv4:    map[string]string{"arp_filter": ""},
			wantErr: true,
		},
		{
			name:    "interface invalid leaf rejected",
			ifv4:    map[string]string{"arp filter": "1"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSysctl(tc.global, tc.ifv4, tc.ifv6)
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

	t.Run("global keys split verbatim", func(t *testing.T) {
		cfg := types.DeviceConfig{
			Sysctl: map[string]string{
				"net.ipv4.conf.all.rp_filter": "0",
				"net.core.somaxconn":          "500",
			},
		}
		got := buildSysctlSettings(cfg, "eth0")
		require.ElementsMatch(t, []tables.Sysctl{
			{Name: []string{"net", "core", "somaxconn"}, Val: "500"},
			{Name: []string{"net", "ipv4", "conf", "all", "rp_filter"}, Val: "0"},
		}, got)
	})

	t.Run("interface keys scoped to the live interface name", func(t *testing.T) {
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

	t.Run("interface name with dots is a single segment", func(t *testing.T) {
		cfg := types.DeviceConfig{
			InterfaceSysctlIPv4: map[string]string{"arp_filter": "1"},
		}
		got := buildSysctlSettings(cfg, "eth0.100")
		require.Equal(t, []tables.Sysctl{
			{Name: []string{"net", "ipv4", "conf", "eth0.100", "arp_filter"}, Val: "1"},
		}, got)
	})
}
