// Copyright 2020 Authors of Cilium
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

package enirouting

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/mac"
)

// RoutingInfo represents information that's required to enable
// connectivity via the local rule and route tables while in ENI mode. The
// information in this struct is used to create rules and routes which direct
// traffic out of the ENI devices (egress).
//
// This struct is mostly derived from the `ipam.AllocationResult` as the
// information comes from IPAM.
type RoutingInfo struct {
	// IPv4Gateway is the gateway where outbound/egress traffic is directed.
	IPv4Gateway net.IP

	// IPv4CIDRs is a list of CIDRs which the ENI device has access to. In most
	// cases, it'll at least contain the CIDR of the IPv4Gateway IP address.
	IPv4CIDRs []net.IPNet

	// MasterIfMAC is the MAC address of the master interface that egress
	// traffic is directed to. This is the MAC of the ENI itself which
	// corresponds to the IPv4Gateway IP addr.
	MasterIfMAC mac.MAC
}

// NewRoutingInfo creates a new RoutingInfo struct, from data that will be
// parsed and validated. Note, this code assumes IPv4 values because ENI + IPv4
// is the only supported path currently.
func NewRoutingInfo(gateway string, cidrs []string, mac string) (*RoutingInfo, error) {
	return parse(gateway, cidrs, mac)
}

func parse(gateway string, cidrs []string, macAddr string) (*RoutingInfo, error) {
	ip := net.ParseIP(gateway)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip: %s", gateway)
	}

	if cidrs == nil || len(cidrs) == 0 {
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

	return &RoutingInfo{
		IPv4Gateway: ip,
		IPv4CIDRs:   parsedCIDRs,
		MasterIfMAC: parsedMAC,
	}, nil
}
