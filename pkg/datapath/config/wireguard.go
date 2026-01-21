// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/vishvananda/netlink"

	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

// Wireguard returns a [BPFWireguard].
func Wireguard(lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
	cfg := NewBPFWireguard(NodeConfig(lnc))

	cfg.InterfaceIfIndex = uint32(link.Attrs().Index)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = option.Config.DatapathMode == datapathOption.DatapathModeNetkit ||
		option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2

	cfg.EphemeralMin = lnc.EphemeralMin

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	return cfg
}
