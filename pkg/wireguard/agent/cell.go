// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/wireguard/types"
)

var Cell = cell.Module(
	"wireguard-agent",
	"Manages WireGuard device and peers",

	cell.Provide(newWireguardAgent, newWireguardConfig),
	cell.ProvidePrivate(buildConfigFrom),
)

// newWireguardAgent returns the [*Agent] as an interface [types.WireguardAgent].
func newWireguardAgent(p params) types.WireguardAgent {
	return newAgent(p)
}

// newWireguardConfig returns the [Config] as an interface [types.WireguardConfig].
func newWireguardConfig(c Config) types.WireguardConfig {
	return c
}

// buildConfigFrom creates the [Config] from [option.DaemonConfig].
func buildConfigFrom(dc *option.DaemonConfig) Config {
	return Config{
		EnableWireguard: dc.EnableWireguard,
	}
}

// Final config of the WireGuard agent.
type Config struct {
	EnableWireguard bool
}

// Returns true when enabled. Implements [types.WireguardConfig].
func (c Config) Enabled() bool {
	return c.EnableWireguard
}
