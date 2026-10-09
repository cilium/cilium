// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
)

var (
	errInvalidSysctlLeaf = errors.New("invalid sysctl leaf parameter")
	errEmptySysctlValue  = errors.New("sysctl value must not be empty")
)

func (d *DeviceConfig) Validate(ipv4Enabled bool, ipv6Enabled bool) error {
	if d == nil {
		return fmt.Errorf("device config is nil")
	}

	if err := validateInterfaceName(d.PodIfName); err != nil {
		return fmt.Errorf("invalid podIfName: %w", err)
	}

	if err := d.validateInterfaceSysctl(); err != nil {
		return fmt.Errorf("invalid sysctl config: %w", err)
	}

	if err := d.validateAddressAllocation(ipv4Enabled, ipv6Enabled); err != nil {
		return fmt.Errorf("invalid address allocation: %w", err)
	}

	return nil
}

func (d *DeviceConfig) validateAddressAllocation(ipv4Enabled bool, ipv6Enabled bool) error {
	if !ipv4Enabled && !ipv6Enabled {
		// we should have at least one of IPv4 or IPv6 enabled
		return fmt.Errorf("both IPv4 and IPv6 are disabled")
	}

	if !ipv4Enabled && d.IPv4Addr.IsValid() {
		return fmt.Errorf("static IPv4 address is not allowed when IPv4 is disabled")
	}

	if !ipv6Enabled && d.IPv6Addr.IsValid() {
		return fmt.Errorf("static IPv6 address is not allowed when IPv6 is disabled")
	}

	if d.HasPool() && (d.IPv4Addr.IsValid() || d.IPv6Addr.IsValid()) {
		// If we have the pool name we are in dynamic allocation mode so we mustn't have static IPs.
		return fmt.Errorf("static IPs are not allowed in dynamic allocation mode")
	}

	if !d.HasPool() && !d.IPv4Addr.IsValid() && !d.IPv6Addr.IsValid() {
		// If we don't have a pool, at least one static IP must be provided
		return fmt.Errorf("no static IP provided and no pool configured")
	}
	return nil
}

// validateInterfaceSysctl validates a device config's interface-scoped
// sysctl leaves at claim preparation time: pure, no I/O. Only the leaf
// (e.g. "arp_filter") is user-controlled; the net.<family>.conf.<interface>.
// prefix is added later, in buildSysctlSettings, once the allocated
// interface's final name is known.
func (cfg *DeviceConfig) validateInterfaceSysctl() error {
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

// validateInterfaceName validates an interface name according to Linux rules
func validateInterfaceName(name string) error {
	// Empty name is valid (means no custom rename)
	if name == "" {
		return nil
	}

	// Check length limit (Linux IFNAMSIZ - 1)
	if len(name) > MaxInterfaceNameLength {
		return fmt.Errorf(
			"interface name too long: %q (%d chars, max %d)",
			name, len(name), MaxInterfaceNameLength)
	}

	// Check for valid characters
	if !validIfNameRegex.MatchString(name) {
		return fmt.Errorf(
			"interface name contains invalid characters: %q (allowed: a-z A-Z 0-9 . _ -)",
			name)
	}

	// Check for reserved names
	if name == "lo" {
		return fmt.Errorf("interface name %q is reserved (loopback)", name)
	}

	if len(name) >= 7 && name[:7] == "cilium_" {
		return fmt.Errorf("interface name %q is reserved (cilium_ prefix)", name)
	}

	return nil
}
