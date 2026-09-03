// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/option"
)

// XDP returns a [BPFXDP].
func XDP(lnc *Config, link netlink.Link) any {
	cfg := NewBPFXDP(NodeConfig(lnc))

	cfg.InterfaceIfIndex = uint32(link.Attrs().Index)
	cfg.DeviceMTU = uint16(link.Attrs().MTU)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols

	cfg.EphemeralMin = lnc.EphemeralMin

	cfg.EnableXDPPrefilter = option.Config.EnableXDPPrefilter

	cfg.TunnelProtocol = lnc.TunnelProtocol
	cfg.TunnelPort = lnc.TunnelPort

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6FragmentsTracking

	lbRSSCfg := lnc.LoadBalancerRSS
	ipv4Prefix := lbRSSCfg.IPv4Prefix()
	cfg.IPv4RSSPrefix.Addr = ipv4Prefix.Addr().As4()
	cfg.IPv4RSSPrefixBits = uint8(ipv4Prefix.Bits())
	ipv6Prefix := lbRSSCfg.IPv6Prefix()
	cfg.IPv6RSSPrefix.Addr = ipv6Prefix.Addr().As16()
	cfg.IPv6RSSPrefixBits = uint8(ipv6Prefix.Bits())

	return cfg
}
