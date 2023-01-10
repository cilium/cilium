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
	// IPv4Gateway is the gateway where outbound/egress traffic is directed.
	IPv4Gateway net.IP

	// IPv4CIDRs is a list of CIDRs which the interface has access to. In most
	// cases, it'll at least contain the CIDR of the IPv4Gateway IP address.
	IPv4CIDRs []net.IPNet

	// MasterIfMAC is the MAC address of the master interface that egress
	// traffic is directed to. This is the MAC of the interface itself which
	// corresponds to the IPv4Gateway IP addr.
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

func (info *RoutingInfo) GetMac() mac.MAC {
	return info.MasterIfMAC
}

func (info *RoutingInfo) GetInterfaceNumber() int {
	return info.InterfaceNumber
}

// NewRoutingInfo creates a new RoutingInfo struct, from data that will be
// parsed and validated. Note, this code assumes IPv4 values because IPv4
// (on either ENI or Azure interface) is the only supported path currently.
// Azure does not support masquerade yet (subnets CIDRs aren't provided):
// until it does, we forward a masquerade bool to opt out ipam.Cidrs use.
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

	parsedCIDRs := make([]net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, c, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr: %s", cidr)
		}

		parsedCIDRs = append(parsedCIDRs, *c)
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
		IPv4CIDRs:       parsedCIDRs,
		MasterIfMAC:     parsedMAC,
		Masquerade:      masquerade,
		InterfaceNumber: parsedIfaceNum,
		IpamMode:        ipamMode,
	}, nil
}
