// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
)

var (
	IPv4InternalAddress = tables.TestIPv4InternalAddress.AsSlice()
	IPv4NodePortAddress = tables.TestIPv4NodePortAddress.AsSlice()

	fakeIPv4 = addressFamily{
		router:          net.ParseIP("1.1.1.2"),
		primaryExternal: net.ParseIP("1.1.1.1"),
		allocCIDR:       cidr.MustParseCIDR("1.1.1.0/24"),
	}

	IPv6InternalAddress = tables.TestIPv6InternalAddress.AsSlice()
	IPv6NodePortAddress = tables.TestIPv6NodePortAddress.AsSlice()

	fakeIPv6 = addressFamily{
		router:          net.ParseIP("cafe::2"),
		primaryExternal: net.ParseIP("cafe::1"),
		allocCIDR:       cidr.MustParseCIDR("cafe::/96"),
	}
)

type fakeNodeAddressing struct {
	ipv6 addressFamily
	ipv4 addressFamily
}

// NewIPv6OnlyNodeAddressing returns a new fake node addressing where IPv4 is
// disabled
func NewIPv6OnlyNodeAddressing() types.NodeAddressing {
	return &fakeNodeAddressing{
		ipv4: addressFamily{},
		ipv6: fakeIPv6,
	}
}

// NewIPv4OnlyNodeAddressing returns a new fake node addressing where IPv6 is
// disabled
func NewIPv4OnlyNodeAddressing() types.NodeAddressing {
	return &fakeNodeAddressing{
		ipv4: fakeIPv4,
		ipv6: addressFamily{},
	}
}

// NewNodeAddressing returns a new fake node addressing
func NewNodeAddressing() types.NodeAddressing {
	return &fakeNodeAddressing{
		ipv4: fakeIPv4,
		ipv6: fakeIPv6,
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

func (a *addressFamily) DirectRouting() (int, net.IP, bool) {
	return 0, nil, false
}

func (n *fakeNodeAddressing) IPv6() types.NodeAddressingFamily {
	return &n.ipv6
}

func (n *fakeNodeAddressing) IPv4() types.NodeAddressingFamily {
	return &n.ipv4
}
