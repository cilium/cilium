// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/types"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/option"
)

// Endpoint returns a [BPFLXC] for an Endpoint.
func Endpoint(ep endpoint.Config, lnc *Config) any {
	cfg := NewBPFLXC(NodeConfig(lnc))

	if option.Config.EnableBPFMasquerade && option.Config.EnableIPv6Masquerade {
		var excludeCIDR *cidr.CIDR
		if option.Config.EnableIPMasqAgent {
			excludeCIDR = option.Config.IPv6NativeRoutingCIDR
		} else {
			excludeCIDR = lnc.NativeRoutingCIDRIPv6
		}

		if excludeCIDR != nil {
			if ip16 := excludeCIDR.IP.To16(); ip16 != nil {
				cfg.IPv6SNATExclusionDstCIDR = cast[types.V6Addr](ip16)
			}
			if mask16 := excludeCIDR.Mask; len(mask16) == 16 {
				cfg.IPv6SNATExclusionDstCIDRMask = cast[types.V6Addr](mask16)
			}
			ones, _ := excludeCIDR.Mask.Size()
			cfg.IPv6SNATExclusionDstCIDRLen = uint16(ones)
		}
	}

	if ep.IPv4Address().IsValid() {
		cfg.EndpointIPv4.Addr = ep.IPv4Address().As4()
	}
	if ep.IPv6Address().IsValid() {
		cfg.EndpointIPv6.Addr = ep.IPv6Address().As16()
	}

	// Netkit devices can be L2-less, meaning they operate with a zero MAC
	// address. Unlike other L2-less devices, the ethernet header length remains
	// at its default non-zero value.
	em := ep.GetNodeMAC()
	if len(em) == 6 {
		cfg.InterfaceMAC.Addr = em.As6()
	}

	cfg.InterfaceIfIndex = uint32(ep.GetIfIndex())
	cfg.DeviceMTU = uint16(lnc.DeviceMTU)

	cfg.EndpointID = uint16(ep.GetID())
	cfg.EndpointNetNSCookie = ep.GetEndpointNetNsCookie()

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	cfg.PolicyVerdictLogFilter = ep.GetPolicyVerdictLogFilter()

	cfg.HostEPID = uint16(lnc.HostEndpointID)
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPAddrToHost32(option.Config.VtepCidrMask)
	}

	cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableICMPRule = option.Config.EnableICMPRules
	cfg.EnableLRP = option.Config.EnableLocalRedirectPolicy

	cfg.EphemeralMin = lnc.EphemeralMin

	cfg.EnablePolicyAccounting = lnc.EnablePolicyAccounting
	cfg.DebugLB = ep.GetOptions().IsEnabled(option.DebugLB)

	if lnc.DatapathIsLayer2 {
		cfg.EnableARPResponder = !ep.RequireARPPassthrough()
	}

	cfg.TunnelProtocol = lnc.TunnelProtocol
	cfg.TunnelPort = lnc.TunnelPort

	cfg.RtInfo, _ = ep.GetRTInfo()

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6FragmentsTracking

	return cfg
}
