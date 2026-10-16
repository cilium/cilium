// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/defaults"
)

// IPv6Gateway returns the IPv6 gateway address for endpoints.
func IPv6Gateway(addr *models.NodeAddressing) netip.Addr {
	// The host's IP is the gateway address
	return addr.IPv6.IP.Addr
}

// IPv4Gateway returns the IPv4 gateway address for endpoints.
func IPv4Gateway(addr *models.NodeAddressing) netip.Addr {
	// The host's IP is the gateway address
	return addr.IPv4.IP.Addr
}

// IPv6Routes returns IPv6 routes to be installed in endpoint's networking namespace.
func IPv6Routes(addr *models.NodeAddressing, linkMTU int) ([]route.Route, error) {
	if !addr.IPv6.IP.IsValid() {
		return []route.Route{}, fmt.Errorf("Missing IPv6 host address")
	}
	ip := net.IP(addr.IPv6.IP.AsSlice())
	return []route.Route{
		{
			Prefix: net.IPNet{
				IP:   ip,
				Mask: defaults.ContainerIPv6Mask,
			},
		},
		{
			Prefix:  defaults.IPv6DefaultRoute,
			Nexthop: &ip,
			MTU:     linkMTU,
		},
	}, nil
}

// IPv4Routes returns IPv4 routes to be installed in endpoint's networking namespace.
func IPv4Routes(addr *models.NodeAddressing, linkMTU int) ([]route.Route, error) {
	if !addr.IPv4.IP.IsValid() {
		return []route.Route{}, fmt.Errorf("Missing IPv4 host address")
	}
	ip := net.IP(addr.IPv4.IP.AsSlice())
	return []route.Route{
		{
			Prefix: net.IPNet{
				IP:   ip,
				Mask: defaults.ContainerIPv4Mask,
			},
		},
		{
			Prefix:  defaults.IPv4DefaultRoute,
			Nexthop: &ip,
			MTU:     linkMTU,
		},
	}, nil
}

// SufficientAddressing returns an error if the provided NodeAddressing does
// not provide sufficient information to derive all IPAM required settings.
func SufficientAddressing(addr *models.NodeAddressing) error {
	if addr == nil {
		return fmt.Errorf("Cilium daemon did not provide addressing information")
	}

	if addr.IPv6 != nil && addr.IPv6.IP.IsValid() {
		return nil
	}

	if addr.IPv4 != nil && addr.IPv4.IP.IsValid() {
		return nil
	}

	return fmt.Errorf("Either IPv4 or IPv6 addressing must be provided")
}
