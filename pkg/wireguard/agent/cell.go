// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	k8sLabels "k8s.io/apimachinery/pkg/labels"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"wireguard-agent",
	"Manages WireGuard device and peers",

	cell.Config(UserConfig{}),
	cell.Provide(newWireguardAgent),
	cell.ProvidePrivate(newConfig),
)

const (
	EnableWireguardFlag              = "enable-wireguard"
	WireguardPersistentKeepaliveFlag = "wireguard-persistent-keepalive"
	WireguardTrackAllIPsFallbackFlag = "wireguard-track-all-ips-fallback"
)

type UserConfig struct {
	EnableWireguard              bool
	WireguardTrackAllIPsFallback bool
	WireguardPersistentKeepalive time.Duration
}

func (uc UserConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableWireguardFlag, uc.EnableWireguard, "Enable WireGuard")
	flags.Duration(WireguardPersistentKeepaliveFlag, uc.WireguardPersistentKeepalive, "The Wireguard keepalive interval as a Go duration string")
	flags.Bool(WireguardTrackAllIPsFallbackFlag, uc.WireguardTrackAllIPsFallback, "Force WireGuard to track all IPs")
	flags.MarkHidden(WireguardTrackAllIPsFallbackFlag)
}

type Config struct {
	UserConfig

	StateDir         string
	EnableIPv4       bool
	EnableIPv6       bool
	TunnelingEnabled bool

	EncryptNode                bool
	NodeEncryptionOptOutLabels k8sLabels.Selector
}

func newConfig(uc UserConfig, dc *option.DaemonConfig) Config {
	return Config{
		UserConfig: uc,

		StateDir:         dc.StateDir,
		EnableIPv4:       dc.EnableIPv4,
		EnableIPv6:       dc.EnableIPv6,
		TunnelingEnabled: dc.TunnelingEnabled(),

		EncryptNode:                dc.EncryptNode,
		NodeEncryptionOptOutLabels: dc.NodeEncryptionOptOutLabels,
	}
}
