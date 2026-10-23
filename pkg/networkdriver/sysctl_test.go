// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

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
