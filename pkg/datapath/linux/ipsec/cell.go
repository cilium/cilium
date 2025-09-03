// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

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

// buildConfigFrom creates the [Config] from [option.DaemonConfig].
func buildConfigFrom(dc *option.DaemonConfig) Config {
	return Config{
		EnableIPsec:                              dc.EnableIPSec,
		EnableIPsecKeyWatcher:                    dc.EnableIPsecKeyWatcher,
		EnableIPsecXfrmStateCaching:              dc.EnableIPSecXfrmStateCaching,
		EnableIPsecEncryptedOverlay:              dc.EnableIPSecEncryptedOverlay,
		UseCiliumInternalIPForIPsec:              dc.UseCiliumInternalIPForIPsec,
		DNSProxyInsecureSkipTransparentModeCheck: dc.DNSProxyInsecureSkipTransparentModeCheck,
		IPsecKeyFile:                             dc.IPSecKeyFile,
		IPsecKeyRotationDuration:                 dc.IPsecKeyRotationDuration,
		EncryptNode:                              dc.EncryptNode,
	}
}

type Config struct {
	EnableIPsec                              bool
	EnableIPsecKeyWatcher                    bool
	EnableIPsecXfrmStateCaching              bool
	EnableIPsecEncryptedOverlay              bool
	UseCiliumInternalIPForIPsec              bool
	DNSProxyInsecureSkipTransparentModeCheck bool
	IPsecKeyFile                             string
	IPsecKeyRotationDuration                 time.Duration
	EncryptNode                              bool
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
