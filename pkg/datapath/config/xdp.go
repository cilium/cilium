// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/vishvananda/netlink"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

// XDP returns a [BPFXDP].
func XDP(lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
	cfg := NewBPFXDP(NodeConfig(lnc))

	cfg.InterfaceIfIndex = uint32(link.Attrs().Index)
	cfg.DeviceMTU = uint16(link.Attrs().MTU)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols

	cfg.EphemeralMin = lnc.EphemeralMin

	cfg.EnableXDPPrefilter = option.Config.EnableXDPPrefilter

	cfg.TunnelProtocol = lnc.TunnelProtocol
	cfg.TunnelPort = lnc.TunnelPort

	return cfg
}
