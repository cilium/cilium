// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/byteorder"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

// Overlay returns a [BPFOverlay].
func Overlay(lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
	cfg := NewBPFOverlay(NodeConfig(lnc))

	cfg.InterfaceIfIndex = uint32(link.Attrs().Index)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableNetkit = option.Config.DatapathMode == datapathOption.DatapathModeNetkit ||
		option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask))
	}

	cfg.EncryptionStrictIngress = option.Config.EnableEncryptionStrictModeIngress

	cfg.EphemeralMin = lnc.EphemeralMin

	return cfg
}
