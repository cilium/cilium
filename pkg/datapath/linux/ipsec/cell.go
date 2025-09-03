// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// The IPsec agent handles key-related initialisation tasks for the ipsec subsystem.
var Cell = cell.Module(
	"ipsec-agent",
	"Handles initial key setup and knows the key size",

	cell.Config(defaultUserConfig),
	cell.Provide(newIPsecAgent, newIPsecConfig),
	cell.ProvidePrivate(buildConfigFrom),
)

type params struct {
	cell.In

	Lifecycle cell.Lifecycle

	Log            *slog.Logger
	JobGroup       job.Group
	LocalNodeStore *node.LocalNodeStore
	Config         Config
	EncryptMap     encrypt.EncryptMap
}

// newIPsecAgent returns the [*Agent] as an interface [types.IPsecAgent].
func newIPsecAgent(p params) types.IPsecAgent {
	return newAgent(p.Lifecycle, p.Log, p.JobGroup, p.LocalNodeStore, p.Config, p.EncryptMap)
}

// newIPsecAgent returns the [Config] as an interface [types.IPsecConfig].
func newIPsecConfig(c Config) types.IPsecConfig {
	return c
}

// buildConfigFrom creates the [Config] from [UserConfig] and [option.DaemonConfig].
func buildConfigFrom(uc UserConfig, dc *option.DaemonConfig) Config {
	return Config{
		UserConfig: uc,

		EncryptNode: dc.EncryptNode,
	}
}

var defaultUserConfig = UserConfig{
	EnableIPsec:                              false,
	EnableIPsecKeyWatcher:                    true,
	EnableIPsecXfrmStateCaching:              true,
	EnableIPsecEncryptedOverlay:              false,
	UseCiliumInternalIPForIPsec:              false,
	DNSProxyInsecureSkipTransparentModeCheck: false,
	IPsecKeyFile:                             "",
	IPsecKeyRotationDuration:                 5 * time.Minute,
}

type UserConfig struct {
	EnableIPsec                              bool
	EnableIPsecKeyWatcher                    bool
	EnableIPsecXfrmStateCaching              bool
	EnableIPsecEncryptedOverlay              bool
	UseCiliumInternalIPForIPsec              bool
	DNSProxyInsecureSkipTransparentModeCheck bool
	IPsecKeyFile                             string
	IPsecKeyRotationDuration                 time.Duration
}

func (def UserConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(types.EnableIPSec, def.EnableIPsec, "Enable IPsec")
	flags.Bool(types.EnableIPsecKeyWatcher, def.EnableIPsecKeyWatcher, "Enable watcher for IPsec key. If disabled, a restart of the agent will be necessary on key rotations.")
	flags.Bool(types.EnableIPSecXfrmStateCaching, def.EnableIPsecXfrmStateCaching, "Enable XfrmState cache for IPSec. Significantly reduces CPU usage in large clusters.")
	flags.MarkHidden(types.EnableIPSecXfrmStateCaching)
	flags.Bool(types.EnableIPSecEncryptedOverlay, def.EnableIPsecEncryptedOverlay, "Enable IPsec encrypted overlay. If enabled tunnel traffic will be encrypted before leaving the host. Requires ipsec and tunnel mode vxlan to be enabled.")
	flags.Bool(types.UseCiliumInternalIPForIPsec, def.UseCiliumInternalIPForIPsec, "Use the CiliumInternalIPs (vs. NodeInternalIPs) for IPsec encapsulation")
	flags.MarkHidden(types.UseCiliumInternalIPForIPsec)
	flags.Bool(types.DNSProxyInsecureSkipTransparentModeCheck, def.DNSProxyInsecureSkipTransparentModeCheck, "Allows DNS proxy transparent mode to be disabled even if encryption is enabled. Enabling this flag and disabling DNS proxy transparent mode will cause proxied DNS traffic to leave the node unencrypted.")
	flags.MarkHidden(types.DNSProxyInsecureSkipTransparentModeCheck)
	flags.String(types.IPSecKeyFile, def.IPsecKeyFile, "Path to IPsec key file")
	flags.Duration(types.IPsecKeyRotationDuration, def.IPsecKeyRotationDuration, "Maximum duration of the IPsec key rotation. The previous key will be removed after that delay.")
}

type Config struct {
	UserConfig

	EncryptNode bool
}

func (c Config) Enabled() bool {
	return c.EnableIPsec
}

func (c Config) EncryptedOverlayEnabled() bool {
	return c.EnableIPsecEncryptedOverlay
}

func (c Config) UseCiliumInternalIP() bool {
	return c.UseCiliumInternalIPForIPsec
}

func (c Config) DNSProxyInsecureSkipTransparentModeCheckEnabled() bool {
	return c.DNSProxyInsecureSkipTransparentModeCheck
}
