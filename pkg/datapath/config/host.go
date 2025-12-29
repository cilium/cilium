// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/byteorder"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	wgtypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// CiliumHost returns a [BPFHost] for attaching bpf_host.c to cilium_host.
func CiliumHost(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) any {
	cfg := NewBPFHost(NodeConfig(lnc))

	em := ep.GetNodeMAC()
	if len(em) != 6 {
		panic(fmt.Sprintf("invalid MAC address for cilium_host: %q", em))
	}
	cfg.InterfaceMAC = em.As8()

	cfg.InterfaceIfIndex = uint32(ep.GetIfIndex())

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	cfg.HostEPID = uint16(lnc.HostEndpointID)
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	if lnc.EnableWireguard {
		cfg.WGIfIndex = lnc.WireguardIfIndex
		cfg.WGPort = wgtypes.ListenPort
	}

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask))
	}

	if option.Config.EnableL2Announcements {
		cfg.EnableL2Announcements = true
		cfg.L2AnnouncementsMaxLiveness = uint64(option.Config.L2AnnouncerLeaseDuration.Nanoseconds())
	}

	cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableICMPRule = option.Config.EnableICMPRules

	cfg.EphemeralMin = lnc.EphemeralMin

	cfg.EnablePolicyAccounting = lnc.EnablePolicyAccounting

	cfg.TunnelProtocol = lnc.TunnelProtocol
	cfg.TunnelPort = lnc.TunnelPort

	return cfg
}

// CiliumNet returns a [BPFHost] for attaching bpf_host.c to cilium_net.
func CiliumNet(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
	cfg := NewBPFHost(NodeConfig(lnc))

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	em := mac.MAC(link.Attrs().HardwareAddr)
	if len(em) != 6 {
		panic(fmt.Sprintf("invalid MAC address for %s: %q", link.Attrs().Name, em))
	}
	cfg.InterfaceMAC = em.As8()

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	ifindex := link.Attrs().Index
	cfg.InterfaceIfIndex = uint32(ifindex)

	cfg.HostEPID = uint16(lnc.HostEndpointID)

	if lnc.EnableWireguard {
		cfg.WGIfIndex = lnc.WireguardIfIndex
		cfg.WGPort = wgtypes.ListenPort
	}

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask))
	}

	cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableICMPRule = option.Config.EnableICMPRules

	cfg.EphemeralMin = lnc.EphemeralMin

	cfg.EnablePolicyAccounting = lnc.EnablePolicyAccounting

	cfg.TunnelProtocol = lnc.TunnelProtocol
	cfg.TunnelPort = lnc.TunnelPort

	return cfg
}

// Netdev returns a [BPFHost] for attaching bpf_host.c to an externally-facing
// network device.
func Netdev(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link, masq4, masq6 netip.Addr) any {
	cfg := NewBPFHost(NodeConfig(lnc))

	// External devices can be L2-less, in which case it won't have a MAC address
	// and its ethernet header length is set to 0.
	em := mac.MAC(link.Attrs().HardwareAddr)
	if len(em) == 6 {
		cfg.InterfaceMAC = em.As8()
	} else {
		cfg.EthHeaderLength = 0
	}

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	ifindex := link.Attrs().Index
	cfg.InterfaceIfIndex = uint32(ifindex)

	// Enable masquerading on external interfaces.
	if option.Config.EnableBPFMasquerade {
		if option.Config.EnableIPv4Masquerade && masq4.IsValid() {
			cfg.NATIPv4Masquerade = masq4.As4()
		}
		if option.Config.EnableIPv6Masquerade && masq6.IsValid() {
			cfg.NATIPv6Masquerade = masq6.As16()
		}
		// Masquerading IPv4 traffic from endpoints leaving the host.
		cfg.EnableRemoteNodeMasquerade = option.Config.EnableRemoteNodeMasquerade
	}

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.HostEPID = uint16(lnc.HostEndpointID)
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	if lnc.EnableWireguard {
		cfg.WGIfIndex = lnc.WireguardIfIndex
		cfg.WGPort = wgtypes.ListenPort
	}

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask))
	}

	if option.Config.EnableL2Announcements {
		cfg.EnableL2Announcements = true
		cfg.L2AnnouncementsMaxLiveness = uint64(option.Config.L2AnnouncerLeaseDuration.Nanoseconds())
	}

	cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableICMPRule = option.Config.EnableICMPRules

	cfg.EphemeralMin = lnc.EphemeralMin

	cfg.EnablePolicyAccounting = lnc.EnablePolicyAccounting

	cfg.TunnelProtocol = lnc.TunnelProtocol
	cfg.TunnelPort = lnc.TunnelPort

	return cfg
}
