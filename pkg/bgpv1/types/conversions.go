// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"net/netip"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// SessionState as defined in rfc4271#section-8.2.2
type SessionState uint32

const (
	SessionUnknown SessionState = iota
	SessionIdle
	SessionConnect
	SessionActive
	SessionOpenSent
	SessionOpenConfirm
	SessionEstablished
)

func (s SessionState) String() string {
	switch s {
	case SessionUnknown:
		return "unknown"
	case SessionIdle:
		return "idle"
	case SessionConnect:
		return "connect"
	case SessionActive:
		return "active"
	case SessionOpenSent:
		return "open_sent"
	case SessionOpenConfirm:
		return "open_confirm"
	case SessionEstablished:
		return "established"
	default:
		return "unknown"
	}
}

// Afi is address family identifier
type Afi uint32

const (
	AfiUnknown Afi = 0
	AfiIPv4    Afi = 1
	AfiIPv6    Afi = 2
	AfiL2VPN   Afi = 25
	AfiLS      Afi = 16388
	AfiOpaque  Afi = 16397
)

// FromString assigns s to a. An error is returned if s is
// an unknown address family indicator.
func (a *Afi) FromString(s string) error {
	switch s {
	case "ipv4":
		*a = AfiIPv4
	case "ipv6":
		*a = AfiIPv6
	case "l2vpn":
		*a = AfiL2VPN
	case "ls":
		*a = AfiLS
	case "opaque":
		*a = AfiOpaque
	default:
		return fmt.Errorf("Unknown Afi: %s", s)
	}
	return nil
}

// String returns the stringified form of a.
func (a Afi) String() string {
	switch a {
	case AfiUnknown:
		return "unknown"
	case AfiIPv4:
		return "ipv4"
	case AfiIPv6:
		return "ipv6"
	case AfiL2VPN:
		return "l2vpn"
	case AfiLS:
		return "ls"
	case AfiOpaque:
		return "opaque"
	default:
		return "unknown"
	}
}

// ParseAfi parses s as an address family identifier.
// If s is unknown, AfiUnknown is returned.
func ParseAfi(s string) Afi {
	var ret Afi
	switch s {
	case "ipv4":
		ret = AfiIPv4
	case "ipv6":
		ret = AfiIPv6
	case "l2vpn":
		ret = AfiL2VPN
	case "ls":
		ret = AfiLS
	case "opaque":
		ret = AfiOpaque
	default:
		ret = AfiUnknown
	}
	return ret
}

// Safi is subsequent address family identifier
type Safi uint32

const (
	SafiUnknown                Safi = 0
	SafiUnicast                Safi = 1
	SafiMulticast              Safi = 2
	SafiMplsLabel              Safi = 4
	SafiEncapsulation          Safi = 7
	SafiVpls                   Safi = 65
	SafiEvpn                   Safi = 70
	SafiLs                     Safi = 71
	SafiSrPolicy               Safi = 73
	SafiMup                    Safi = 85
	SafiMplsVpn                Safi = 128
	SafiMplsVpnMulticast       Safi = 129
	SafiRouteTargetConstraints Safi = 132
	SafiFlowSpecUnicast        Safi = 133
	SafiFlowSpecVpn            Safi = 134
	SafiKeyValue               Safi = 241
)

// FromString assigns safi to s. An error is returned if safi
// is an unknown subsequent address family indicator.
func (s *Safi) FromString(safi string) error {
	switch safi {
	case "unicast":
		*s = SafiUnicast
	case "multicast":
		*s = SafiMulticast
	case "mpls_label":
		*s = SafiMplsLabel
	case "encapsulation":
		*s = SafiEncapsulation
	case "vpls":
		*s = SafiVpls
	case "evpn":
		*s = SafiEvpn
	case "ls":
		*s = SafiLs
	case "sr_policy":
		*s = SafiSrPolicy
	case "mup":
		*s = SafiMup
	case "mpls_vpn":
		*s = SafiMplsVpn
	case "mpls_vpn_multicast":
		*s = SafiMplsVpnMulticast
	case "route_target_constraints":
		*s = SafiRouteTargetConstraints
	case "flowspec_unicast":
		*s = SafiFlowSpecUnicast
	case "flowspec_vpn":
		*s = SafiFlowSpecVpn
	case "key_value":
		*s = SafiKeyValue
	default:
		return fmt.Errorf("Unknown Safi: %s", s)
	}
	return nil
}

// String returns the stringified form of s.
func (s Safi) String() string {
	switch s {
	case SafiUnknown:
		return "unknown"
	case SafiUnicast:
		return "unicast"
	case SafiMulticast:
		return "multicast"
	case SafiMplsLabel:
		return "mpls_label"
	case SafiEncapsulation:
		return "encapsulation"
	case SafiVpls:
		return "vpls"
	case SafiEvpn:
		return "evpn"
	case SafiLs:
		return "ls"
	case SafiSrPolicy:
		return "sr_policy"
	case SafiMup:
		return "mup"
	case SafiMplsVpn:
		return "mpls_vpn"
	case SafiMplsVpnMulticast:
		return "mpls_vpn_multicast"
	case SafiRouteTargetConstraints:
		return "route_target_constraints"
	case SafiFlowSpecUnicast:
		return "flowspec_unicast"
	case SafiFlowSpecVpn:
		return "flowspec_vpn"
	case SafiKeyValue:
		return "key_value"
	default:
		return "unknown"
	}
}

// ParseSafi parses s as a subsequent address family identifier.
// If s is unknown, SafiUnknown is returned.
func ParseSafi(s string) Safi {
	var ret Safi
	switch s {
	case "unicast":
		ret = SafiUnicast
	case "multicast":
		ret = SafiMulticast
	case "mpls_label":
		ret = SafiMplsLabel
	case "encapsulation":
		ret = SafiEncapsulation
	case "vpls":
		ret = SafiVpls
	case "evpn":
		ret = SafiEvpn
	case "ls":
		ret = SafiLs
	case "sr_policy":
		ret = SafiSrPolicy
	case "mup":
		ret = SafiMup
	case "mpls_vpn":
		ret = SafiMplsVpn
	case "mpls_vpn_multicast":
		ret = SafiMplsVpnMulticast
	case "route_target_constraints":
		ret = SafiRouteTargetConstraints
	case "flowspec_unicast":
		ret = SafiFlowSpecUnicast
	case "flowspec_vpn":
		ret = SafiFlowSpecVpn
	case "key_value":
		ret = SafiKeyValue
	default:
		ret = SafiUnknown
	}
	return ret
}

func ToAgentFamily(fam v2.CiliumBGPFamily) Family {
	return Family{
		Afi:  ParseAfi(fam.Afi),
		Safi: ParseSafi(fam.Safi),
	}
}

// ToNeighborV1 converts a CiliumBGPNeighbor to Neighbor which can be used
// with Router API. The caller must ensure that the an is not nil.
func ToNeighborV1(an *v2alpha1.CiliumBGPNeighbor, password string) *Neighbor {
	n := &Neighbor{}

	n.Address = toPeerAddressV1(an.PeerAddress)
	n.ASN = uint32(an.PeerASN)
	n.AuthPassword = password
	n.EbgpMultihop = toEbgpMultihopV1(an.EBGPMultihopTTL)
	n.Timers = toNeighborTimersV1(
		an.ConnectRetryTimeSeconds,
		an.HoldTimeSeconds,
		an.KeepAliveTimeSeconds,
	)
	n.Transport = toNeighborTransportV1(an.PeerPort)
	n.GracefulRestart = toNeighborGracefulRestartV1(an.GracefulRestart)
	n.AfiSafis = toNeighborAfiSafisV1(an.Families)

	return n
}

func toPeerAddressV1(apiPeerAddress string) netip.Addr {
	// API uses CIDR notation, but gobgp uses IP address notation.
	prefix, err := netip.ParsePrefix(apiPeerAddress)
	if err != nil {
		return netip.Addr{}
	}
	return prefix.Addr()
}

func toEbgpMultihopV1(apiTTL *int32) *NeighborEbgpMultihop {
	if apiTTL == nil {
		return nil
	}
	return &NeighborEbgpMultihop{
		TTL: uint32(*apiTTL),
	}
}

func toNeighborTimersV1(connectRetry, holdTime, keepaliveInterval *int32) *NeighborTimers {
	if connectRetry == nil && holdTime == nil && keepaliveInterval == nil {
		return nil
	}

	timers := &NeighborTimers{}

	if connectRetry != nil {
		timers.ConnectRetry = uint64(*connectRetry)
	}

	if holdTime != nil {
		timers.HoldTime = uint64(*holdTime)
	}

	if keepaliveInterval != nil {
		timers.KeepaliveInterval = uint64(*keepaliveInterval)
	}

	return timers
}

func toNeighborTransportV1(apiPeerPort *int32) *NeighborTransport {
	if apiPeerPort == nil {
		return nil
	}
	return &NeighborTransport{
		RemotePort: uint32(*apiPeerPort),
	}
}

func toNeighborGracefulRestartV1(apiGracefulRestart *v2alpha1.CiliumBGPNeighborGracefulRestart) *NeighborGracefulRestart {
	if apiGracefulRestart == nil || apiGracefulRestart.RestartTimeSeconds == nil {
		return nil
	}
	return &NeighborGracefulRestart{
		Enabled:     apiGracefulRestart.Enabled,
		RestartTime: uint32(*apiGracefulRestart.RestartTimeSeconds),
	}
}

func toNeighborAfiSafisV1(apiFamilies []v2alpha1.CiliumBGPFamily) []*Family {
	if len(apiFamilies) == 0 {
		return nil
	}

	afisafis := make([]*Family, 0, len(apiFamilies))

	for _, apiFamily := range apiFamilies {
		afisafis = append(afisafis, &Family{
			Afi:  ParseAfi(apiFamily.Afi),
			Safi: ParseSafi(apiFamily.Safi),
		})
	}

	return afisafis
}

// ToNeighborV2 converts a CiliumBGPNodePeer to Neighbor which can be used
// with Router API. The caller must ensure that the np, np.PeerAddress,
// np.PeerASN and pc are not nil.
func ToNeighborV2(np *v2.CiliumBGPNodePeer, pc *v2.CiliumBGPPeerConfigSpec, password string) *Neighbor {
	neighbor := &Neighbor{}

	neighbor.Address = toPeerAddressV2(*np.PeerAddress)
	neighbor.ASN = uint32(*np.PeerASN)
	neighbor.AuthPassword = password
	neighbor.EbgpMultihop = toNeighborEbgpMultihopV2(pc.EBGPMultihop)
	neighbor.Timers = toNeighborTimersV2(pc.Timers)
	neighbor.Transport = toNeighborTransportV2(np.LocalAddress, pc.Transport)
	neighbor.GracefulRestart = toNeighborGracefulRestartV2(pc.GracefulRestart)
	neighbor.AfiSafis = toNeighborAfiSafisV2(pc.Families)

	return neighbor
}

func toPeerAddressV2(peerAddress string) netip.Addr {
	addr, err := netip.ParseAddr(peerAddress)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

func toNeighborEbgpMultihopV2(ebgpMultihop *int32) *NeighborEbgpMultihop {
	if ebgpMultihop == nil || *ebgpMultihop <= 1 {
		return nil
	}
	return &NeighborEbgpMultihop{
		TTL: uint32(*ebgpMultihop),
	}
}

func toNeighborTimersV2(apiTimers *v2.CiliumBGPTimers) *NeighborTimers {
	if apiTimers == nil {
		return nil
	}

	timers := &NeighborTimers{}

	if apiTimers.ConnectRetryTimeSeconds != nil {
		timers.ConnectRetry = uint64(*apiTimers.ConnectRetryTimeSeconds)
	}

	if apiTimers.HoldTimeSeconds != nil {
		timers.HoldTime = uint64(*apiTimers.HoldTimeSeconds)
	}

	if apiTimers.KeepAliveTimeSeconds != nil {
		timers.KeepaliveInterval = uint64(*apiTimers.KeepAliveTimeSeconds)
	}

	return timers
}

func toNeighborTransportV2(apiLocalAddress *string, apiTransport *v2.CiliumBGPTransport) *NeighborTransport {
	if apiLocalAddress == nil && apiTransport == nil {
		return nil
	}

	transport := &NeighborTransport{}

	if apiLocalAddress != nil {
		transport.LocalAddress = *apiLocalAddress
	}

	if apiTransport != nil {
		if apiTransport.PeerPort != nil {
			transport.RemotePort = uint32(*apiTransport.PeerPort)
		}
	}

	return transport
}

func toNeighborGracefulRestartV2(apiGR *v2.CiliumBGPNeighborGracefulRestart) *NeighborGracefulRestart {
	if apiGR == nil || apiGR.RestartTimeSeconds == nil {
		return nil
	}
	return &NeighborGracefulRestart{
		Enabled:     apiGR.Enabled,
		RestartTime: uint32(*apiGR.RestartTimeSeconds),
	}
}

func toNeighborAfiSafisV2(families []v2.CiliumBGPFamilyWithAdverts) []*Family {
	if len(families) == 0 {
		return nil
	}

	afiSafis := []*Family{}

	for _, family := range families {
		afiSafis = append(afiSafis, &Family{
			Afi:  ParseAfi(family.Afi),
			Safi: ParseSafi(family.Safi),
		})
	}

	return afiSafis
}
