// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const (
	sysctlNetPrefix = "net"
	sysctlConf      = "conf"
	sysctlNeigh     = "neigh"
)

// sysctlPseudoInterfaces are the non-interface conf/neigh groups allowed in the
// global sysctl block.
var sysctlPseudoInterfaces = []string{"all", "default"}

// validateSysctl validates a network config's sysctl settings at claim
// preparation time. It is pure (no I/O) and delegates parameter well-formedness
// to sysctl.ValidateParameter. Global keys targeting a specific interface are
// rejected; those belong in ifv4/ifv6, which are scoped to the allocated
// interface at apply time (see buildSysctlSettings).
func validateSysctl(global, ifv4, ifv6 map[string]string) error {
	for key, val := range global {
		segments := strings.Split(key, ".")
		if err := sysctl.ValidateParameter(segments); err != nil {
			return err
		}
		if val == "" {
			return fmt.Errorf("sysctl %q has an empty value", key)
		}
		if iface, scoped := globalSysctlInterface(segments); scoped {
			return fmt.Errorf("sysctl %q targets a specific interface %q; "+
				"use interfaceSysctl to configure settings for the allocated interface", key, iface)
		}
	}

	// Only the leaf is user-controlled; the net.<family>.conf.<interface>.
	// prefix is added at apply time.
	if err := validateInterfaceSysctl("ipv4", ifv4); err != nil {
		return err
	}
	if err := validateInterfaceSysctl("ipv6", ifv6); err != nil {
		return err
	}

	return nil
}

// validateInterfaceSysctl validates the leaf parameters of an interface-scoped
// sysctl map for a single address family.
func validateInterfaceSysctl(family string, leaves map[string]string) error {
	for leaf, val := range leaves {
		if err := sysctl.ValidateParameter(strings.Split(leaf, ".")); err != nil {
			return fmt.Errorf("invalid interfaceSysctl %s leaf %q: %w", family, leaf, err)
		}
		if val == "" {
			return fmt.Errorf("interfaceSysctl %s %q has an empty value", family, leaf)
		}
	}
	return nil
}

// globalSysctlInterface reports whether a global sysctl key targets a specific
// named interface (and returns that name). net.<family>.conf.<name>.* and
// net.<family>.neigh.<name>.* are interface-scoped, unless <name> is an
// "all"/"default" pseudo-interface.
func globalSysctlInterface(segments []string) (string, bool) {
	if len(segments) < 5 {
		return "", false
	}
	if segments[0] != sysctlNetPrefix {
		return "", false
	}
	if segments[2] != sysctlConf && segments[2] != sysctlNeigh {
		return "", false
	}
	name := segments[3]
	if slices.Contains(sysctlPseudoInterfaces, name) {
		return "", false
	}
	return name, true
}

// interfaceSysctlName builds the full parameter for an interface-scoped leaf:
// net.<family>.conf.<ifName>.<leaf...>. ifName stays a single segment so names
// containing dots (VLAN interfaces like "eth0.100") are handled unambiguously.
func interfaceSysctlName(family, ifName, leaf string) []string {
	return append([]string{sysctlNetPrefix, family, sysctlConf, ifName}, strings.Split(leaf, ".")...)
}

// buildSysctlSettings expands a device config's sysctl settings into
// tables.Sysctl ready to apply inside the pod netns: global keys verbatim,
// interface keys scoped to ifName. Order is unspecified; each setting targets a
// distinct /proc/sys path.
func buildSysctlSettings(cfg types.DeviceConfig, ifName string) []tables.Sysctl {
	var settings []tables.Sysctl

	for key, val := range cfg.Sysctl {
		settings = append(settings, tables.Sysctl{Name: strings.Split(key, "."), Val: val})
	}
	for leaf, val := range cfg.InterfaceSysctlIPv4 {
		settings = append(settings, tables.Sysctl{Name: interfaceSysctlName("ipv4", ifName, leaf), Val: val})
	}
	for leaf, val := range cfg.InterfaceSysctlIPv6 {
		settings = append(settings, tables.Sysctl{Name: interfaceSysctlName("ipv6", ifName, leaf), Val: val})
	}

	return settings
}
