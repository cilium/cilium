// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	config_latest "github.com/cilium/cilium/pkg/datapath/config/latest"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
)

func NodeConfig(lnc *datapath.LocalNodeConfiguration) *config_latest.Node {
	node := config_latest.NewNode()
	node.ClusterIdBits = identity.GetClusterIDBits()

	node.CiliumHostIfindex = lnc.CiliumHostIfIndex
	node.CiliumHostMac = lnc.CiliumHostMAC.AsSlice()
	node.CiliumNetIfindex = lnc.CiliumNetIfIndex
	node.CiliumNetMac = lnc.CiliumNetMAC.AsSlice()

	if lnc.ServiceLoopbackIPv4.IsValid() {
		node.ServiceLoopbackIpv4 = lnc.ServiceLoopbackIPv4.AsSlice()
	}

	if lnc.ServiceLoopbackIPv6.IsValid() {
		node.ServiceLoopbackIpv6 = lnc.ServiceLoopbackIPv6.AsSlice()
	}

	if lnc.CiliumInternalIPv6.IsValid() {
		node.RouterIpv6 = lnc.CiliumInternalIPv6.AsSlice()
	}

	node.ClusterId = option.Config.ClusterID
	node.TracePayloadLen = uint32(option.Config.TracePayloadlen)
	node.TracePayloadLenOverlay = uint32(option.Config.TracePayloadlenOverlay)

	if lnc.DirectRoutingDevice != nil {
		node.DirectRoutingDevIfindex = uint32(lnc.DirectRoutingDevice.Index)
	}

	node.SupportsFibLookupSkipNeigh = probes.HaveFibLookupSkipNeigh() == nil

	node.TracingIpOptionType = uint32(option.Config.IPTracingOptionType)

	if option.Config.PolicyDenyResponse == option.PolicyDenyResponseIcmp {
		node.PolicyDenyResponseEnabled = true
	} else {
		node.PolicyDenyResponseEnabled = false
	}

	node.NodeportPortMin = uint32(lnc.LBConfig.NodePortMin)
	node.NodeportPortMax = uint32(lnc.LBConfig.NodePortMax)

	if option.Config.EnableNat46X64Gateway {
		node.Nat_46X64Prefix = option.Config.IPv6NAT46x64CIDRBase.AsSlice()
	}

	node.EnableJiffies = option.Config.ClockSource == option.ClockSourceJiffies
	node.KernelHz = uint32(option.Config.KernelHz)

	node.EnableConntrackAccounting = lnc.EnableConntrackAccounting

	node.DebugLb = option.Config.Opts.IsEnabled(option.DebugLB)

	node.HashInit4Seed = lnc.MaglevConfig.SeedJhash0
	node.HashInit6Seed = lnc.MaglevConfig.SeedJhash1

	node.EnableTproxy = option.Config.EnableBPFTProxy

	return node
}
