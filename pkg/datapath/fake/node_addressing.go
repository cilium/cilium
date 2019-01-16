// Copyright 2018-2019 Authors of Cilium
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

package fake

import (
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath"
)

type fakeNodeAddressing struct {
	ipv6 addressFamily
	ipv4 addressFamily
}

// NewNodeAddressing returns a new fake node addressing
func NewNodeAddressing() datapath.NodeAddressing {
	return &fakeNodeAddressing{
		ipv4: addressFamily{
			router:          net.ParseIP("1.1.1.2"),
			primaryExternal: net.ParseIP("1.1.1.1"),
			allocCIDR:       cidr.MustParseCIDR("1.1.1.0/24"),
		},
		ipv6: addressFamily{
			router:          net.ParseIP("cafe::2"),
			primaryExternal: net.ParseIP("cafe::1"),
			allocCIDR:       cidr.MustParseCIDR("cafe::/96"),
		},
	}
}

type addressFamily struct {
	router          net.IP
	primaryExternal net.IP
	allocCIDR       *cidr.CIDR
}

func (a *addressFamily) Router() net.IP {
	return a.router
}

func (a *addressFamily) PrimaryExternal() net.IP {
	return a.primaryExternal
}

func (a *addressFamily) AllocationCIDR() *cidr.CIDR {
	return a.allocCIDR
}

func (n *fakeNodeAddressing) IPv6() datapath.NodeAddressingFamily {
	return &n.ipv6
}

func (n *fakeNodeAddressing) IPv4() datapath.NodeAddressingFamily {
	return &n.ipv4
}
