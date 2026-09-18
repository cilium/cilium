// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import "github.com/spf13/pflag"

const (
	// EnableNetworkDriver enables the Cilium Network Driver.
	EnableNetworkDriver = "enable-network-driver"

	// EnableNetworkDriverIPv4 enables IPv4 address assignment for the Cilium Network Driver.
	EnableNetworkDriverIPv4 = "enable-network-driver-ipv4"

	// EnableNetworkDriverIPv6 enables IPv6 address assignment for the Cilium Network Driver.
	EnableNetworkDriverIPv6 = "enable-network-driver-ipv6"
)

// Config contains configuration shared by the Network Driver agent and operator components.
type Config struct {
	Enabled     bool `mapstructure:"enable-network-driver"`
	IPv4Enabled bool `mapstructure:"enable-network-driver-ipv4"`
	IPv6Enabled bool `mapstructure:"enable-network-driver-ipv6"`
}

// DefaultConfig is the default Network Driver configuration.
var DefaultConfig = Config{
	Enabled:     false,
	IPv4Enabled: true,
	IPv6Enabled: false,
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableNetworkDriver, cfg.Enabled,
		"Enable the Cilium Network Driver to assign interfaces via Dynamic Resource Allocation")
	flags.Bool(EnableNetworkDriverIPv4, cfg.IPv4Enabled,
		"Enable IPv4 address assignment for Cilium Network Driver resources")
	flags.Bool(EnableNetworkDriverIPv6, cfg.IPv6Enabled,
		"Enable IPv6 address assignment for Cilium Network Driver resources")
}
