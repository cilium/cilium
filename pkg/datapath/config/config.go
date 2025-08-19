// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

func NodeConfig(lnc *datapath.LocalNodeConfiguration) Node {
	node := *NewNode()

	if lnc.ServiceLoopbackIPv4 != nil {
		node.ServiceLoopbackIPv4 = [4]byte(lnc.ServiceLoopbackIPv4.To4())
	}

	if lnc.ServiceLoopbackIPv6 != nil {
		node.ServiceLoopbackIPv6 = [16]byte(lnc.ServiceLoopbackIPv6.To16())
	}

	if lnc.CiliumInternalIPv6 != nil {
		node.RouterIPv6 = ([16]byte)(lnc.CiliumInternalIPv6.To16())
	}

	node.TracePayloadLen = uint32(option.Config.TracePayloadlen)
	node.TracePayloadLenOverlay = uint32(option.Config.TracePayloadlenOverlay)

	if lnc.DirectRoutingDevice != nil {
		node.DirectRoutingDevIfindex = uint32(lnc.DirectRoutingDevice.Index)
	}

	node.SupportsFibLookupSkipNeigh = probes.HaveFibLookupSkipNeigh() == nil

	node.TracingIPOptionType = uint8(option.Config.IPTracingOptionType)

	return node
}
