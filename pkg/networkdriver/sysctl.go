// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"strings"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// buildSysctlSettings expands a device config's interface-scoped sysctl
// leaves into tables.Sysctl, ready to apply inside the pod netns once the
// interface has its final name. ifName is kept as a single path segment so
// names containing dots (e.g. "eth0.100") are handled unambiguously.
func buildSysctlSettings(cfg types.DeviceConfig, ifName string) []tables.Sysctl {
	settings := appendSysctlSettings(nil, "ipv4", ifName, cfg.InterfaceSysctlIPv4)
	settings = appendSysctlSettings(settings, "ipv6", ifName, cfg.InterfaceSysctlIPv6)
	return settings
}

func appendSysctlSettings(settings []tables.Sysctl, family, ifName string, leaves map[string]string) []tables.Sysctl {
	for leaf, val := range leaves {
		name := append([]string{"net", family, "conf", ifName}, strings.Split(leaf, ".")...)
		settings = append(settings, tables.Sysctl{Name: name, Val: val})
	}
	return settings
}
