// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"github.com/cilium/cilium/pkg/datapath/config"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

func nodeConfig(lnc *datapath.LocalNodeConfiguration) config.Node {
	node := *config.NewNode()

	if lnc.ServiceLoopbackIPv4 != nil {
		node.ServiceLoopbackIPv4 = [4]byte(lnc.ServiceLoopbackIPv4.To4())
	}

	if lnc.CiliumInternalIPv6 != nil {
		node.RouterIPv6 = ([16]byte)(lnc.CiliumInternalIPv6.To16())
	}

	if lnc.ServiceLoopbackIPv6 != nil {
		node.ServiceLoopbackIPv6 = ([16]byte)(lnc.ServiceLoopbackIPv6.To16())
	}

	return node
}
