// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/byteorder"
	config_latest "github.com/cilium/cilium/pkg/datapath/config/latest"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

// Overlay returns a [BPFOverlay].
func Overlay(lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
	cfg := config_latest.NewBPFOverlay(NodeConfig(lnc))

	cfg.InterfaceIfindex = uint32(link.Attrs().Index)

	em := mac.MAC(link.Attrs().HardwareAddr)
	if len(em) == 6 {
		cfg.InterfaceMac = em.AsSlice()
	}

	cfg.EnableExtendedIpProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	if option.Config.EnableVTEP {
		cfg.VtepMask = byteorder.NetIPAddrToHost32(option.Config.VtepCidrMask)
	}

	cfg.EncryptionStrictIngress = option.Config.EnableEncryptionStrictModeIngress

	cfg.EphemeralMin = uint32(lnc.EphemeralMin)

	cfg.TunnelProtocol = uint32(lnc.TunnelProtocol)
	cfg.TunnelPort = uint32(lnc.TunnelPort)

	cfg.EnableIpv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIpv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	return cfg
}
