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
// connectivity via the local rule and route tables while in ENI or Azure IPAM mode.
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

	// IPv4CIDRs is a list of IPv4 CIDRs which the interface has access to. In most
	// cases, it'll at least contain the CIDR of the IPv4Gateway IP address.
	IPv4CIDRs []net.IPNet

	// IPv6CIDRs is a list of IPv6 CIDRs which the interface has access to. In most
	// cases, it'll at least contain the CIDR of the IPv6Gateway IP address.
	IPv6CIDRs []net.IPNet

	// MasterIfMAC is the MAC address of the master interface that egress
	// traffic is directed to. This is the MAC of the interface itself which
	// corresponds to the IPv4Gateway or IPv6Gateway IP address.
	MasterIfMAC mac.MAC

	// Masquerade represents whether masquerading is enabled or not.
	Masquerade bool

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
// parsed and validated. Azure does not support masquerade yet (subnets CIDRs
// aren't provided): until it does, we forward a masquerade bool to opt out
// ipam.Cidrs use.
func NewRoutingInfo(gateway string, cidrs []string, mac, ifaceNum, ipamMode string, masquerade bool) (*RoutingInfo, error) {
	return parse(gateway, cidrs, mac, ifaceNum, ipamMode, masquerade)
}

func parse(gateway string, cidrs []string, macAddr, ifaceNum, ipamMode string, masquerade bool) (*RoutingInfo, error) {
	ip := net.ParseIP(gateway)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip: %s", gateway)
	}

	if len(cidrs) == 0 && masquerade {
		return nil, errors.New("empty cidrs")
	}

	var ipv4Gateway, ipv6Gateway net.IP
	var ipv4CIDRs, ipv6CIDRs []net.IPNet

	for _, cidr := range cidrs {
		_, c, err := net.ParseCIDR(cidr)
		switch {
		case err != nil:
			return nil, fmt.Errorf("invalid cidr: %s", cidr)
		case c.IP.To4() != nil:
			ipv4CIDRs = append(ipv4CIDRs, *c)
		default:
			ipv6CIDRs = append(ipv6CIDRs, *c)
		}
	}

	if ip.To4() != nil {
		ipv4Gateway = ip
	} else if ip.To16() != nil {
		ipv6Gateway = ip
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
		IPv4Gateway:     ipv4Gateway,
		IPv6Gateway:     ipv6Gateway,
		IPv4CIDRs:       ipv4CIDRs,
		IPv6CIDRs:       ipv6CIDRs,
		MasterIfMAC:     parsedMAC,
		Masquerade:      masquerade,
		InterfaceNumber: parsedIfaceNum,
		IpamMode:        ipamMode,
	}, nil
}
