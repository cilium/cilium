// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/tables"
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

	if option.Config.EnableIPv4 {
		rssPrefix := option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv4
		if rssPrefix.IsValid() {
			cfg.IPv4RSSPrefix.Addr = rssPrefix.Addr().As4()
			cfg.IPv4RSSPrefixBits = uint8(rssPrefix.Bits())
		} else if lnc.DirectRoutingDevice != nil {
			addr := tables.PreferredIPv4Address(lnc.DirectRoutingDevice.Addrs)
			if addr.IsValid() {
				cfg.IPv4RSSPrefix.Addr = addr.As4()
			}
		}
	}

	if option.Config.EnableIPv6 {
		rssPrefix := option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv6
		if rssPrefix.IsValid() {
			cfg.IPv6RSSPrefix.Addr = rssPrefix.Addr().As16()
			cfg.IPv6RSSPrefixBits = uint8(rssPrefix.Bits())
		} else if lnc.DirectRoutingDevice != nil {
			addr := tables.PreferredIPv6Address(lnc.DirectRoutingDevice.Addrs)
			if addr.IsValid() {
				cfg.IPv6RSSPrefix.Addr = addr.As16()
			}
		}
	}

	return cfg
}
