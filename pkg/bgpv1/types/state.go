// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "fmt"

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
