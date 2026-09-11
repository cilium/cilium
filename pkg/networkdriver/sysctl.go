// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// validateInterfaceSysctl validates a device config's interface-scoped
// sysctl leaves at claim preparation time: pure, no I/O. Only the leaf
// (e.g. "arp_filter") is user-controlled; the net.<family>.conf.<interface>.
// prefix is added later, in buildSysctlSettings, once the allocated
// interface's final name is known.
func validateInterfaceSysctl(cfg types.DeviceConfig) error {
	if err := validateSysctlLeaves(cfg.InterfaceSysctlIPv4); err != nil {
		return fmt.Errorf("ipv4: %w", err)
	}
	if err := validateSysctlLeaves(cfg.InterfaceSysctlIPv6); err != nil {
		return fmt.Errorf("ipv6: %w", err)
	}
	return nil
}

func validateSysctlLeaves(leaves map[string]string) error {
	for leaf, val := range leaves {
		if err := sysctl.ValidateParameter(strings.Split(leaf, ".")); err != nil {
			return fmt.Errorf("%w: %q: %w", errInvalidSysctlLeaf, leaf, err)
		}
		if val == "" {
			return fmt.Errorf("%w: %q", errEmptySysctlValue, leaf)
		}
	}
	return nil
}

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
