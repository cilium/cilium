// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/cilium/cilium/pkg/byteorder"
	config_latest "github.com/cilium/cilium/pkg/datapath/config/latest"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

// Endpoint returns a [BPFLXC] for an Endpoint.
func Endpoint(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) any {
	cfg := config_latest.NewBPFLXC(NodeConfig(lnc))

	if ep.IPv4Address().IsValid() {
		cfg.EndpointIpv4 = ep.IPv4Address().AsSlice()
	}
	if ep.IPv6Address().IsValid() {
		cfg.EndpointIpv6 = ep.IPv6Address().AsSlice()
	}

	// Netkit devices can be L2-less, meaning they operate with a zero MAC
	// address. Unlike other L2-less devices, the ethernet header length remains
	// at its default non-zero value.
	em := ep.GetNodeMAC()
	if len(em) == 6 {
		cfg.InterfaceMac = em.AsSlice()
	}

	cfg.InterfaceIfindex = uint32(ep.GetIfIndex())

	cfg.EndpointId = uint32(ep.GetID())
	cfg.EndpointNetnsCookie = ep.GetEndpointNetNsCookie()

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	cfg.PolicyVerdictLogFilter = ep.GetPolicyVerdictLogFilter()

	cfg.HostEpId = uint32(lnc.HostEndpointID)
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableExtendedIpProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	if option.Config.EnableVTEP {
		cfg.VtepMask = byteorder.NetIPAddrToHost32(option.Config.VtepCidrMask)
	}

	cfg.AllowIcmpFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableIcmpRule = option.Config.EnableICMPRules
	cfg.EnableLrp = option.Config.EnableLocalRedirectPolicy

	cfg.EphemeralMin = uint32(lnc.EphemeralMin)

	cfg.EnablePolicyAccounting = lnc.EnablePolicyAccounting
	cfg.Node.DebugLb = ep.GetOptions().IsEnabled(option.DebugLB)

	if lnc.DatapathIsLayer2 {
		cfg.EnableArpResponder = !ep.RequireARPPassthrough()
	}

	cfg.TunnelProtocol = uint32(lnc.TunnelProtocol)
	cfg.TunnelPort = uint32(lnc.TunnelPort)

	cfg.FibTableId = ep.GetFibTableID()

	cfg.EnableIpv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIpv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	return cfg
}
