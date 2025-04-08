// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/config"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

func nodeConfig(lnc *datapath.LocalNodeConfiguration) config.Node {
	node := *config.NewNode()

	if option.Config.EnableIPv4 {
		node.IPv4Loopback = byteorder.NetIPv4ToHost32(lnc.LoopbackIPv4)
	}

	if option.Config.EnableIPv6 && lnc.CiliumInternalIPv6 != nil {
		node.RouterIPv6 = ([16]byte)(lnc.CiliumInternalIPv6)
	}

	return node
}
