// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/vishvananda/netlink"

	config_latest "github.com/cilium/cilium/pkg/datapath/config/latest"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

// Wireguard returns a [BPFWireguard].
func Wireguard(lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
	cfg := config_latest.NewBPFWireguard(NodeConfig(lnc))

	cfg.InterfaceIfindex = uint32(link.Attrs().Index)

	cfg.EnableExtendedIpProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	cfg.EphemeralMin = uint32(lnc.EphemeralMin)

	cfg.TunnelProtocol = uint32(lnc.TunnelProtocol)
	cfg.TunnelPort = uint32(lnc.TunnelPort)

	cfg.EnableIpv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIpv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	return cfg
}
