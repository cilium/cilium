// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/wireguard/types"
)

var Cell = cell.Module(
	"wireguard-agent",
	"Manages WireGuard device and peers",

	cell.Config(defaultUserConfig),
	cell.Provide(newWireguardAgent, newWireguardConfig),
	cell.ProvidePrivate(buildConfigFrom),
)

var OperatorCell = cell.Config(defaultEnableConfig)

// newWireguardAgent returns the [*Agent] as an interface [types.WireguardAgent]
// and the map of macros [defines.NodeOut] for datapath compilation.
func newWireguardAgent(p params) (out struct {
	cell.Out
	types.WireguardAgent
	defines.NodeOut
}) {
	out.WireguardAgent = newAgent(p)
	if out.WireguardAgent.Enabled() {
		out.NodeDefines = map[string]string{
			"ENABLE_WIREGUARD": "1",
		}
		if p.Config.EncryptNode {
			out.NodeDefines["ENABLE_NODE_ENCRYPTION"] = "1"
		}
	}
	return
}

// newWireguardConfig returns the [Config] as an interface [types.WireguardConfig].
func newWireguardConfig(c Config) types.WireguardConfig {
	return c
}

// buildConfigFrom creates the [Config] from [UserConfig] and [option.DaemonConfig].
func buildConfigFrom(uc UserConfig, dc *option.DaemonConfig) Config {
	return Config{
		UserConfig: uc,

		StateDir:         dc.StateDir,
		EnableIPv4:       dc.EnableIPv4,
		EnableIPv6:       dc.EnableIPv6,
		TunnelingEnabled: dc.TunnelingEnabled(),
		EncryptNode:      dc.EncryptNode,
	}
}

var defaultUserConfig = UserConfig{
	EnableConfig:                 defaultEnableConfig,
	WireguardTrackAllIPsFallback: false,
	WireguardPersistentKeepalive: 0,
	NodeEncryptionOptOutLabels:   "node-role.kubernetes.io/control-plane",
}

// User provided flags.
type UserConfig struct {
	EnableConfig                 `mapstructure:",squash"`
	WireguardTrackAllIPsFallback bool
	WireguardPersistentKeepalive time.Duration
	NodeEncryptionOptOutLabels   string
}

func (def UserConfig) Flags(flags *pflag.FlagSet) {
	def.EnableConfig.Flags(flags)
	flags.Duration(types.WireguardPersistentKeepalive, def.WireguardPersistentKeepalive, "The Wireguard keepalive interval as a Go duration string")
	flags.Bool(types.WireguardTrackAllIPsFallback, def.WireguardTrackAllIPsFallback, "Force WireGuard to track all IPs")
	flags.MarkHidden(types.WireguardTrackAllIPsFallback)
	flags.String(types.NodeEncryptionOptOutLabels, def.NodeEncryptionOptOutLabels, "Label selector for nodes which will opt-out of node-to-node encryption")
}

// Final config of the WireGuard agent.
type Config struct {
	UserConfig

	StateDir         string
	EnableIPv4       bool
	EnableIPv6       bool
	TunnelingEnabled bool
	EncryptNode      bool
}

var defaultEnableConfig = EnableConfig{
	EnableWireguard: false,
}

type EnableConfig struct {
	EnableWireguard bool
}

// Returns true when enabled. Implements [types.WireguardConfig].
func (c EnableConfig) Enabled() bool {
	return c.EnableWireguard
}

func (def EnableConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(types.EnableWireguard, def.EnableWireguard, "Enable WireGuard")
}
