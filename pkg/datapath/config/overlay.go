// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

// Overlay returns a [BPFOverlay].
func Overlay(lnc *Config, link netlink.Link) any {
	cfg := NewBPFOverlay(NodeConfig(lnc))

	cfg.InterfaceIfIndex = uint32(link.Attrs().Index)
	cfg.DeviceMTU = uint16(lnc.DeviceMTU)

	em := mac.MAC(link.Attrs().HardwareAddr)
	if len(em) == 6 {
		cfg.InterfaceMAC.Addr = em.As6()
	}

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPAddrToHost32(option.Config.VtepCidrMask)
	}

	cfg.EncryptionStrictIngress = option.Config.EnableEncryptionStrictModeIngress

	cfg.EphemeralMin = lnc.EphemeralMin

	cfg.TunnelProtocol = lnc.TunnelProtocol
	cfg.TunnelPort = lnc.TunnelPort

	if option.Config.EnableBPFMasquerade && option.Config.EnableIPv4Masquerade {
		var excludeCIDR *cidr.CIDR
		if option.Config.EnableIPMasqAgent {

			// native-routing-cidr is optional with ip-masq-agent and may be nil
			excludeCIDR = option.Config.IPv4NativeRoutingCIDR
		} else {
			excludeCIDR = lnc.NativeRoutingCIDRIPv4
		}

		if excludeCIDR != nil {
			cfg.IPv4SNATExclusionDstCIDR = byteorder.NetIPv4ToHost32(excludeCIDR.IP)
			ones, _ := excludeCIDR.Mask.Size()
			cfg.IPv4SNATExclusionDstCIDRLen = uint16(ones)
		}
	}

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6FragmentsTracking

	return cfg
}
