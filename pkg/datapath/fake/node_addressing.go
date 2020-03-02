// Copyright 2018-2020 Authors of Cilium
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

var (
	IPv4InternalAddress = net.ParseIP("2.2.2.2")
	IPv4NodePortAddress = net.ParseIP("3.3.3.3")

	fakeIPv4 = addressFamily{
		router:          net.ParseIP("1.1.1.2"),
		primaryExternal: net.ParseIP("1.1.1.1"),
		allocCIDR:       cidr.MustParseCIDR("1.1.1.0/24"),
		localAddresses: []net.IP{
			net.ParseIP("2.2.2.2"),
			net.ParseIP("3.3.3.3"),
			net.ParseIP("4.4.4.4"),
		},
		lbNodeAddresses: []net.IP{net.IPv4(0, 0, 0, 0), IPv4InternalAddress, IPv4NodePortAddress},
	}

	IPv6InternalAddress = net.ParseIP("f00d::1")
	IPv6NodePortAddress = net.ParseIP("f00d::2")

	fakeIPv6 = addressFamily{
		router:          net.ParseIP("cafe::2"),
		primaryExternal: net.ParseIP("cafe::1"),
		allocCIDR:       cidr.MustParseCIDR("cafe::/96"),
		localAddresses: []net.IP{
			net.ParseIP("f00d::1"),
			net.ParseIP("f00d::2"),
			net.ParseIP("f00d::3"),
		},
		lbNodeAddresses: []net.IP{net.IPv6zero, IPv6InternalAddress, IPv6NodePortAddress},
	}
)

type fakeNodeAddressing struct {
	ipv6 addressFamily
	ipv4 addressFamily
}

// NewIPv6OnlyNodeAddressing returns a new fake node addressing where IPv4 is
// disabled
func NewIPv6OnlyNodeAddressing() datapath.NodeAddressing {
	return &fakeNodeAddressing{
		ipv4: addressFamily{},
		ipv6: fakeIPv6,
	}
}

// NewIPv4OnlyNodeAddressing returns a new fake node addressing where IPv6 is
// disabled
func NewIPv4OnlyNodeAddressing() datapath.NodeAddressing {
	return &fakeNodeAddressing{
		ipv4: fakeIPv4,
		ipv6: addressFamily{},
	}
}

// NewNodeAddressing returns a new fake node addressing
func NewNodeAddressing() datapath.NodeAddressing {
	return &fakeNodeAddressing{
		ipv4: fakeIPv4,
		ipv6: fakeIPv6,
	}
}

type addressFamily struct {
	router          net.IP
	primaryExternal net.IP
	allocCIDR       *cidr.CIDR
	localAddresses  []net.IP
	lbNodeAddresses []net.IP
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

func (a *addressFamily) LocalAddresses() ([]net.IP, error) {
	return a.localAddresses, nil
}

func (a *addressFamily) LoadBalancerNodeAddresses() []net.IP {
	return a.lbNodeAddresses
}

func (n *fakeNodeAddressing) IPv6() datapath.NodeAddressingFamily {
	return &n.ipv6
}

func (n *fakeNodeAddressing) IPv4() datapath.NodeAddressingFamily {
	return &n.ipv4
}
