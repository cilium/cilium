// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

// Wireguard returns a [BPFWireguard].
func Wireguard(lnc *Config, link netlink.Link) any {
	cfg := NewBPFWireguard(NodeConfig(lnc))

	cfg.InterfaceIfIndex = uint32(link.Attrs().Index)
	cfg.DeviceMTU = uint16(lnc.DeviceMTU)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	cfg.EphemeralMin = lnc.EphemeralMin

	cfg.TunnelProtocol = lnc.TunnelProtocol
	cfg.TunnelPort = lnc.TunnelPort

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6FragmentsTracking

	if option.Config.EnableBPFMasquerade && option.Config.EnableIPv6Masquerade {
		var excludeCIDR *cidr.CIDR
		if option.Config.EnableIPMasqAgent {
			excludeCIDR = option.Config.IPv6NativeRoutingCIDR
		} else {
			excludeCIDR = lnc.NativeRoutingCIDRIPv6
		}

		if excludeCIDR != nil {
			if ip16 := excludeCIDR.IP.To16(); ip16 != nil {
				cfg.IPv6SNATExclusionDstCIDR = cast[types.V6Addr](ip16)
			}
			if mask16 := excludeCIDR.Mask; len(mask16) == 16 {
				cfg.IPv6SNATExclusionDstCIDRMask = cast[types.V6Addr](mask16)
			}
			ones, _ := excludeCIDR.Mask.Size()
			cfg.IPv6SNATExclusionDstCIDRLen = uint16(ones)
		}
	}

	return cfg
}
