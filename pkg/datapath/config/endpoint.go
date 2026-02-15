// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"net"

	"github.com/cilium/cilium/pkg/byteorder"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

// Endpoint returns a [BPFLXC] for an Endpoint.
func Endpoint(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) any {
	cfg := NewBPFLXC(NodeConfig(lnc))

	if ep.IPv4Address().IsValid() {
		cfg.EndpointIPv4 = ep.IPv4Address().As4()
	}
	if ep.IPv6Address().IsValid() {
		cfg.EndpointIPv6 = ep.IPv6Address().As16()
	}

	// Netkit devices can be L2-less, meaning they operate with a zero MAC
	// address. Unlike other L2-less devices, the ethernet header length remains
	// at its default non-zero value.
	em := ep.GetNodeMAC()
	if len(em) == 6 {
		cfg.InterfaceMAC = em.As8()
	}

	cfg.InterfaceIfIndex = uint32(ep.GetIfIndex())

	cfg.EndpointID = uint16(ep.GetID())
	cfg.EndpointNetNSCookie = ep.GetEndpointNetNsCookie()

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	cfg.PolicyVerdictLogFilter = ep.GetPolicyVerdictLogFilter()

	cfg.HostEPID = uint16(lnc.HostEndpointID)
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask))
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

	cfg.FIBTableID = ep.GetFibTableID()

	return cfg
}
