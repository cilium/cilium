// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
)

func NodeConfig(lnc *Config) Node {
	node := *NewNode()
	node.ClusterIDBits = identity.GetClusterIDBits()

	node.CiliumHostIfIndex = lnc.CiliumHostIfIndex
	node.CiliumHostMAC.Addr = lnc.CiliumHostMAC.As6()
	node.CiliumNetIfIndex = lnc.CiliumNetIfIndex
	node.CiliumNetMAC.Addr = lnc.CiliumNetMAC.As6()

	if lnc.ServiceLoopbackIPv4.IsValid() {
		node.ServiceLoopbackIPv4.Addr = lnc.ServiceLoopbackIPv4.As4()
	}

	if lnc.ServiceLoopbackIPv6.IsValid() {
		node.ServiceLoopbackIPv6.Addr = lnc.ServiceLoopbackIPv6.As16()
	}

	if lnc.CiliumInternalIPv6.IsValid() {
		node.RouterIPv6.Addr = lnc.CiliumInternalIPv6.As16()
	}

	node.ClusterID = option.Config.ClusterID
	node.TracePayloadLen = uint32(option.Config.TracePayloadlen)
	node.TracePayloadLenOverlay = uint32(option.Config.TracePayloadlenOverlay)

	if lnc.DirectRoutingDevice != nil {
		node.DirectRoutingDevIfIndex = uint32(lnc.DirectRoutingDevice.Index)
	}

	node.SupportsFIBLookupSkipNeigh = probes.HaveFibLookupSkipNeigh() == nil
	node.SupportsFIBLookupSrc = probes.HaveFibLookupSrc() == nil

	// Terminate inbound IPIP in BPF on netdev ingress for any outer dst that
	// resolves to a local endpoint - pod IP (DSR-IPIP) or host IP (hostNetwork
	// backend, --enable-ipip-termination Envoy target). With this in place,
	// cilium_ipip{4,6} are TX-only (egress encap on the LB side) and bpf_host
	// is not attached to them on RX. The inner packet is delivered with
	// skb->dev set to the physical netdev rather than cilium_ipip{4,6}, so any
	// host-side listener that depended on SO_BINDTODEVICE against
	// cilium_ipip{4,6} will no longer match decapped traffic.
	node.EnableIPIPTermination = option.Config.EnableIPIPTermination

	node.EnableNodeportSourceLookup = lnc.LBConfig.NodePortEnableDynamicSourceLookup

	node.LBDefaultAlg = uint8(loadbalancer.SVCLoadBalancingAlgorithmRandom)
	if lnc.LBConfig.LBAlgorithm == loadbalancer.LBAlgorithmMaglev {
		node.LBDefaultAlg = uint8(loadbalancer.SVCLoadBalancingAlgorithmMaglev)
	}
	node.LBSelectionPerService = lnc.LBConfig.AlgorithmAnnotation

	node.TracingIPOptionType = uint8(option.Config.IPTracingOptionType)

	if option.Config.PolicyDenyResponse == option.PolicyDenyResponseIcmp {
		node.PolicyDenyResponseEnabled = true
	} else {
		node.PolicyDenyResponseEnabled = false
	}

	node.NodeportPortMin = lnc.LBConfig.NodePortMin
	node.NodeportPortMax = lnc.LBConfig.NodePortMax

	if option.Config.EnableNat46X64Gateway {
		node.NAT46X64Prefix.Addr = option.Config.IPv6NAT46x64CIDRBase.As4()
	}

	node.EnableJiffies = option.Config.ClockSource == option.ClockSourceJiffies
	node.KernelHz = uint32(option.Config.KernelHz)

	node.EnableConntrackAccounting = lnc.EnableConntrackAccounting

	node.DebugLB = option.Config.Opts.IsEnabled(option.DebugLB)

	node.HashInit4Seed = lnc.MaglevConfig.SeedJhash0
	node.HashInit6Seed = lnc.MaglevConfig.SeedJhash1

	node.EnableTproxy = option.Config.EnableBPFTProxy

	node.EventsMapRateLimit = option.Config.BPFEventsDefaultRateLimit
	node.EventsMapBurstLimit = option.Config.BPFEventsDefaultBurstLimit

	node.EnableEndpointRoutes = option.Config.EnableEndpointRoutes

	node.EnableIdentityMark = option.Config.EnableIdentityMark

	node.EnableBPFHostRouting = !option.Config.UnsafeDaemonConfigOption.EnableHostLegacyRouting

	node.EncryptionStrictIngress = option.Config.EnableEncryptionStrictModeIngress

	return node
}
