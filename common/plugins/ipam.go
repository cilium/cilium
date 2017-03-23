// Copyright 2016-2017 Authors of Cilium
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

package plugins

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
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

type Route struct {
	Prefix  net.IPNet
	Nexthop *net.IP
}

// ByMask is used to sort an array of routes by mask, narrow first.
type ByMask []Route

func (a ByMask) Len() int {
	return len(a)
}

func (a ByMask) Less(i, j int) bool {
	lenA, _ := a[i].Prefix.Mask.Size()
	lenB, _ := a[j].Prefix.Mask.Size()
	return lenA > lenB
}

func (a ByMask) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// IPv6Routes returns IPv6 routes to be installed in endpoint's networking namespace.
func IPv6Routes(addr *models.NodeAddressing) ([]Route, error) {
	ip := net.ParseIP(addr.IPV6.IP)
	if ip == nil {
		return []Route{}, fmt.Errorf("Invalid IP address: %s", addr.IPV6.IP)
	}
	return []Route{
		{
			Prefix: net.IPNet{
				IP:   ip,
				Mask: addressing.ContainerIPv6Mask,
			},
		},
		{
			Prefix:  addressing.IPv6DefaultRoute,
			Nexthop: &ip,
		},
	}, nil
}

// IPv4Routes returns IPv4 routes to be installed in endpoint's networking namespace.
func IPv4Routes(addr *models.NodeAddressing) ([]Route, error) {
	ip := net.ParseIP(addr.IPV4.IP)
	if ip == nil {
		return []Route{}, fmt.Errorf("Invalid IP address: %s", addr.IPV4.IP)
	}
	return []Route{
		{
			Prefix: net.IPNet{
				IP:   ip,
				Mask: addressing.ContainerIPv4Mask,
			},
		},
		{
			Prefix:  addressing.IPv4DefaultRoute,
			Nexthop: &ip,
		},
	}, nil
}

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
