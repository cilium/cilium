// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connector

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/defaults"
)

// IPv6Gateway returns the IPv6 gateway address for endpoints.
func IPv6Gateway(addr *models.NodeAddressing) string {
	// The host's IP is the gateway address
	return addr.IPV6.IP
}

// IPv4Gateway returns the IPv4 gateway address for endpoints.
func IPv4Gateway(addr *models.NodeAddressing) string {
	// The host's IP is the gateway address
	return addr.IPV4.IP
}

// IPv6Routes returns IPv6 routes to be installed in endpoint's networking namespace.
func IPv6Routes(addr *models.NodeAddressing, linkMTU int) ([]route.Route, error) {
	ip := net.ParseIP(addr.IPV6.IP)
	if ip == nil {
		return []route.Route{}, fmt.Errorf("Invalid IP address: %s", addr.IPV6.IP)
	}
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
	ip := net.ParseIP(addr.IPV4.IP)
	if ip == nil {
		return []route.Route{}, fmt.Errorf("Invalid IP address: %s", addr.IPV4.IP)
	}
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

	if addr.IPV6 != nil && addr.IPV6.IP != "" {
		return nil
	}

	if addr.IPV4 != nil && addr.IPV4.IP != "" {
		return nil
	}

	return fmt.Errorf("Either IPv4 or IPv6 addressing must be provided")
}
