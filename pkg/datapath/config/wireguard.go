// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/option"
)

// Wireguard returns a [BPFWireguard].
func Wireguard(lnc *Config, link netlink.Link) any {
	cfg := NewBPFWireguard(NodeConfig(lnc))

	cfg.InterfaceIfIndex = uint32(link.Attrs().Index)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	cfg.EphemeralMin = lnc.EphemeralMin

	cfg.TunnelProtocol = lnc.TunnelProtocol
	cfg.TunnelPort = lnc.TunnelPort

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6FragmentsTracking

	return cfg
}
