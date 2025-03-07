// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/mac"
)

// RoutingInfo represents information that's required to enable
// connectivity via the local rule and route tables while in ENI,Azure IPAM mode and delegated IPAM mode.
// The information in this struct is used to create rules and routes which direct
// traffic out of the interface (egress).
//
// This struct is mostly derived from the `ipam.AllocationResult` as the
// information comes from IPAM.
type RoutingInfo struct {
	// IPv4Gateway is the gateway where outbound/egress IPv4 traffic is directed.
	IPv4Gateway net.IP

	// IPv6Gateway is the gateway where outbound/egress IPv6 traffic is directed.
	IPv6Gateway net.IP

	// IPv4CIDRs is a list of CIDRs which the interface has access to. In most
	// cases, it'll at least contain the CIDR of the IPv4Gateway IP address.
	IPv4CIDRs []net.IPNet

	// IPv6CIDRs is a list of CIDRs which the interface has access to. In most
	// cases, it'll at least contain the CIDR of the IPv6Gateway IP address.
	IPv6CIDRs []net.IPNet

	// MasterIfMAC is the MAC address of the master interface that egress
	// traffic is directed to. This is the MAC of the interface itself which
	// corresponds to the IPv4Gateway IP addr.
	MasterIfMAC mac.MAC

	// Masquerade represents whether masquerading is enabled or not.
	Masquerade bool

	// MasqueradeV6 represents whether masquerading is enabled or not for IPv6.
	MasqueradeV6 bool

	// InterfaceNumber is the generic number of the master interface that
	// egress traffic is directed to. This is used to compute the table ID for
	// the per-ENI tables.
	InterfaceNumber int

	// IpamMode tells us which IPAM mode is being used (e.g., ENI, AKS).
	IpamMode string
}

func (info *RoutingInfo) GetIPv4CIDRs() []net.IPNet {
	return info.IPv4CIDRs
}

func (info *RoutingInfo) GetIPv6CIDRs() []net.IPNet {
	return info.IPv6CIDRs
}

// NewRoutingInfo creates a new RoutingInfo struct, from data that will be
// parsed and validated. Note, this code assumes IPv4 values because IPv4
// (on either ENI or Azure interface) is the only supported path currently.
// Azure does not support masquerade yet (subnets CIDRs aren't provided):
// until it does, we forward a masquerade bool to opt out ipam.Cidrs use.
func NewRoutingInfo(gateway, gatewayV6 string, cidrs []string, mac, ifaceNum, ipamMode string, masquerade, masqueradeV6 bool) (*RoutingInfo, error) {
	return parse(gateway, gatewayV6, cidrs, mac, ifaceNum, ipamMode, masquerade, masqueradeV6)
}

func parse(gateway, gatewayV6 string, cidrs []string, macAddr, ifaceNum, ipamMode string, masquerade, masqueradeV6 bool) (*RoutingInfo, error) {
	ip := net.ParseIP(gateway)
	ipv6 := net.ParseIP(gatewayV6)
	if ip == nil && ipv6 == nil {
		return nil, fmt.Errorf("invalid gateway, ipv4: %s, ipv6: %s", gateway, gatewayV6)
	}
	if ip != nil && ip.To4() == nil {
		return nil, fmt.Errorf("invalid ipv4 gateway: %s", gateway)
	}
	if ipv6 != nil && ipv6.To4() != nil {
		return nil, fmt.Errorf("invalid ipv6 gateway: %s", gateway)
	}

	if len(cidrs) == 0 && masquerade {
		return nil, errors.New("empty cidrs")
	}

	parsedIPv4CIDRs := make([]net.IPNet, 0, len(cidrs))
	parsedIPv6CIDRs := make([]net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, c, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr: %s", cidr)
		}
		if c.IP.To4() != nil {
			parsedIPv4CIDRs = append(parsedIPv4CIDRs, *c)
		} else {
			parsedIPv6CIDRs = append(parsedIPv6CIDRs, *c)
		}
	}

	parsedMAC, err := mac.ParseMAC(macAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid mac: %s", macAddr)
	}

	parsedIfaceNum, err := strconv.Atoi(ifaceNum)
	if err != nil {
		return nil, fmt.Errorf("invalid interface number: %s", ifaceNum)
	}

	return &RoutingInfo{
		IPv4Gateway:     ip,
		IPv6Gateway:     ipv6,
		IPv4CIDRs:       parsedIPv4CIDRs,
		IPv6CIDRs:       parsedIPv6CIDRs,
		MasterIfMAC:     parsedMAC,
		Masquerade:      masquerade,
		InterfaceNumber: parsedIfaceNum,
		IpamMode:        ipamMode,
	}, nil
}
