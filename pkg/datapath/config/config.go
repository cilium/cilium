// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
)

func NodeConfig(lnc *datapath.LocalNodeConfiguration) Node {
	node := *NewNode()
	node.ClusterIDBits = identity.GetClusterIDBits()

	node.CiliumHostIfIndex = lnc.CiliumHostIfIndex
	node.CiliumHostMAC = lnc.CiliumHostMAC.As8()
	node.CiliumNetIfIndex = lnc.CiliumNetIfIndex
	node.CiliumNetMAC = lnc.CiliumNetMAC.As8()

	if lnc.ServiceLoopbackIPv4 != nil {
		node.ServiceLoopbackIPv4 = [4]byte(lnc.ServiceLoopbackIPv4.To4())
	}

	if lnc.ServiceLoopbackIPv6 != nil {
		node.ServiceLoopbackIPv6 = [16]byte(lnc.ServiceLoopbackIPv6.To16())
	}

	if lnc.CiliumInternalIPv6 != nil {
		node.RouterIPv6 = ([16]byte)(lnc.CiliumInternalIPv6.To16())
	}

	node.ClusterID = option.Config.ClusterID
	node.TracePayloadLen = uint32(option.Config.TracePayloadlen)
	node.TracePayloadLenOverlay = uint32(option.Config.TracePayloadlenOverlay)

	if lnc.DirectRoutingDevice != nil {
		node.DirectRoutingDevIfIndex = uint32(lnc.DirectRoutingDevice.Index)
	}

	node.SupportsFIBLookupSkipNeigh = probes.HaveFibLookupSkipNeigh() == nil

	node.TracingIPOptionType = uint8(option.Config.IPTracingOptionType)

	if option.Config.PolicyDenyResponse == option.PolicyDenyResponseIcmp {
		node.PolicyDenyResponseEnabled = true
	} else {
		node.PolicyDenyResponseEnabled = false
	}

	node.NodeportPortMin = lnc.LBConfig.NodePortMin
	node.NodeportPortMax = lnc.LBConfig.NodePortMax

	if option.Config.EnableNat46X64Gateway {
		node.NAT46X64Prefix = option.Config.IPv6NAT46x64CIDRBase.As4()
	}

	node.EnableJiffies = option.Config.ClockSource == option.ClockSourceJiffies
	node.KernelHz = uint32(option.Config.KernelHz)

	node.EnableConntrackAccounting = lnc.EnableConntrackAccounting

	node.DebugLB = option.Config.Opts.IsEnabled(option.DebugLB)

	node.HashInit4Seed = lnc.MaglevConfig.SeedJhash0
	node.HashInit6Seed = lnc.MaglevConfig.SeedJhash1

	node.EventsMapRateLimit = option.Config.BPFEventsDefaultRateLimit
	node.EventsMapBurstLimit = option.Config.BPFEventsDefaultBurstLimit

	return node
}
