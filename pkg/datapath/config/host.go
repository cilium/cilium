// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/byteorder"
	config_latest "github.com/cilium/cilium/pkg/datapath/config/latest"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	wgtypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// CiliumHost returns a [BPFHost] for attaching bpf_host.c to cilium_host.
func CiliumHost(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) any {
	cfg := config_latest.NewBPFHost(NodeConfig(lnc))

	em := ep.GetNodeMAC()
	if len(em) != 6 {
		panic(fmt.Sprintf("invalid MAC address for cilium_host: %q", em))
	}
	cfg.InterfaceMac = em.AsSlice()

	cfg.InterfaceIfindex = uint32(ep.GetIfIndex())

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	cfg.HostEpId = uint32(lnc.HostEndpointID)
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	if lnc.EnableWireguard {
		cfg.WgIfindex = lnc.WireguardIfIndex
		cfg.WgPort = wgtypes.ListenPort
	}

	if option.Config.EnableVTEP {
		cfg.VtepMask = byteorder.NetIPAddrToHost32(option.Config.VtepCidrMask)
	}

	if option.Config.EnableL2Announcements {
		cfg.EnableL2Announcements = true
		cfg.L2AnnouncementsMaxLiveness = uint64(option.Config.L2AnnouncerLeaseDuration.Nanoseconds())
	}

	cfg.AllowIcmpFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableIcmpRule = option.Config.EnableICMPRules

	cfg.EphemeralMin = uint32(lnc.EphemeralMin)

	cfg.EnablePolicyAccounting = lnc.EnablePolicyAccounting

	cfg.TunnelProtocol = uint32(lnc.TunnelProtocol)
	cfg.TunnelPort = uint32(lnc.TunnelPort)

	cfg.EnableIpv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIpv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	return cfg
}

// CiliumNet returns a [BPFHost] for attaching bpf_host.c to cilium_net.
func CiliumNet(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
	cfg := &config_latest.BPFHost{Node: NodeConfig(lnc)}

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	em := mac.MAC(link.Attrs().HardwareAddr)
	if len(em) != 6 {
		panic(fmt.Sprintf("invalid MAC address for %s: %q", link.Attrs().Name, em))
	}
	cfg.InterfaceMac = em.AsSlice()

	cfg.EnableExtendedIpProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	ifindex := link.Attrs().Index
	cfg.InterfaceIfindex = uint32(ifindex)

	cfg.HostEpId = uint32(lnc.HostEndpointID)

	if lnc.EnableWireguard {
		cfg.WgIfindex = lnc.WireguardIfIndex
		cfg.WgPort = wgtypes.ListenPort
	}

	if option.Config.EnableVTEP {
		cfg.VtepMask = byteorder.NetIPAddrToHost32(option.Config.VtepCidrMask)
	}

	cfg.AllowIcmpFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableIcmpRule = option.Config.EnableICMPRules

	cfg.EphemeralMin = uint32(lnc.EphemeralMin)

	cfg.EnablePolicyAccounting = lnc.EnablePolicyAccounting

	cfg.TunnelProtocol = uint32(lnc.TunnelProtocol)
	cfg.TunnelPort = uint32(lnc.TunnelPort)

	cfg.EnableIpv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIpv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	return cfg
}

// Netdev returns a [BPFHost] for attaching bpf_host.c to an externally-facing
// network device.
func Netdev(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link, masq4, masq6 netip.Addr) any {
	cfg := &config_latest.BPFHost{Node: NodeConfig(lnc)}

	// External devices can be L2-less, in which case it won't have a MAC address
	// and its ethernet header length is set to 0.
	em := mac.MAC(link.Attrs().HardwareAddr)
	if len(em) == 6 {
		cfg.InterfaceMac = em.AsSlice()
	} else {
		cfg.EthHeaderLength = 0
	}

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	ifindex := link.Attrs().Index
	cfg.InterfaceIfindex = uint32(ifindex)

	// Enable masquerading on external interfaces.
	if option.Config.EnableBPFMasquerade {
		if option.Config.EnableIPv4Masquerade && masq4.IsValid() {
			cfg.NatIpv4Masquerade = masq4.AsSlice()
		}
		if option.Config.EnableIPv6Masquerade && masq6.IsValid() {
			cfg.NatIpv6Masquerade = masq6.AsSlice()
		}
		// Masquerading IPv4 traffic from endpoints leaving the host.
		cfg.EnableRemoteNodeMasquerade = option.Config.EnableRemoteNodeMasquerade
	}

	cfg.EnableExtendedIpProtocols = option.Config.EnableExtendedIPProtocols
	cfg.HostEpId = uint32(lnc.HostEndpointID)
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableNetkit = lnc.DatapathIsNetkit

	if lnc.EnableWireguard {
		cfg.WgIfindex = lnc.WireguardIfIndex
		cfg.WgPort = wgtypes.ListenPort
	}

	if option.Config.EnableVTEP {
		cfg.VtepMask = byteorder.NetIPAddrToHost32(option.Config.VtepCidrMask)
	}

	if option.Config.EnableL2Announcements {
		cfg.EnableL2Announcements = true
		cfg.L2AnnouncementsMaxLiveness = uint64(option.Config.L2AnnouncerLeaseDuration.Nanoseconds())
	}

	cfg.AllowIcmpFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableIcmpRule = option.Config.EnableICMPRules

	cfg.EphemeralMin = uint32(lnc.EphemeralMin)

	cfg.EnablePolicyAccounting = lnc.EnablePolicyAccounting

	cfg.TunnelProtocol = uint32(lnc.TunnelProtocol)
	cfg.TunnelPort = uint32(lnc.TunnelPort)

	cfg.EnableIpv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIpv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	switch link.(type) {
	case *netlink.Bridge:
		// When a bridge device has br_netfilter with bridge-nf-call-iptables=1,
		// the packet must be hairpinned via cilium_net instead of punting to the
		// stack, because ip_sabotage_in() would skip the TPROXY rule. We simplify
		// the logic by always hairpinning to the proxy when it's a bridge.
		cfg.ProxyRedirectViaCiliumNet = true
	}

	return cfg
}
