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

	if option.Config.EnableIPv4 {
		if option.Config.LoadBalancerRSSv4CIDR != "" {
			cfg.IPv4RSSPrefix.Addr = option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv4.Addr().As4()
			cfg.IPv4RSSPrefixBits = uint8(option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv4.Bits())
		} else {
			if lnc.DirectRoutingDevice != nil {
				for _, addr := range lnc.DirectRoutingDevice.Addrs {
					if addr.Addr.Is4() {
						cfg.IPv4RSSPrefix.Addr = addr.Addr.As4()
						break
					}
				}
			}
		}
	}

	if option.Config.EnableIPv6 {
		if option.Config.LoadBalancerRSSv6CIDR != "" {
			cfg.IPv6RSSPrefix.Addr = option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv6.Addr().As16()
			cfg.IPv6RSSPrefixBits = uint8(option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv6.Bits())
		} else {
			if lnc.DirectRoutingDevice != nil {
				for _, addr := range lnc.DirectRoutingDevice.Addrs {
					if addr.Addr.Is6() {
						cfg.IPv6RSSPrefix.Addr = addr.Addr.As16()
						if !addr.Addr.IsLinkLocalUnicast() {
							break
						}
					}
				}
			}
		}
	}

	return cfg
}
