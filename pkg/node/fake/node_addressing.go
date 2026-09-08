// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/node"
)

var (
	IPv4InternalAddress = tables.TestIPv4InternalAddress.AsSlice()
	IPv4NodePortAddress = tables.TestIPv4NodePortAddress.AsSlice()

	fakeIPv4 = addressFamily{
		router:          netip.MustParseAddr("1.1.1.2"),
		primaryExternal: netip.MustParseAddr("1.1.1.1"),
		allocCIDR:       netip.MustParsePrefix("1.1.1.0/24"),
	}

	IPv6InternalAddress = tables.TestIPv6InternalAddress.AsSlice()
	IPv6NodePortAddress = tables.TestIPv6NodePortAddress.AsSlice()

	fakeIPv6 = addressFamily{
		router:          netip.MustParseAddr("cafe::2"),
		primaryExternal: netip.MustParseAddr("cafe::1"),
		allocCIDR:       netip.MustParsePrefix("cafe::/96"),
	}
)

type nodeAddressing struct {
	ipv6 addressFamily
	ipv4 addressFamily
}

// NewIPv6OnlyAddressing returns a new fake node addressing where IPv4 is
// disabled
func NewIPv6OnlyAddressing() node.Addressing {
	return &nodeAddressing{
		ipv4: addressFamily{},
		ipv6: fakeIPv6,
	}
}

// NewIPv4OnlyAddressing returns a new fake node addressing where IPv6 is
// disabled
func NewIPv4OnlyAddressing() node.Addressing {
	return &nodeAddressing{
		ipv4: fakeIPv4,
		ipv6: addressFamily{},
	}
}

// NewAddressing returns a new fake node addressing
func NewAddressing() node.Addressing {
	return &nodeAddressing{
		ipv4: fakeIPv4,
		ipv6: fakeIPv6,
	}
}

type addressFamily struct {
	router          netip.Addr
	primaryExternal netip.Addr
	allocCIDR       netip.Prefix
}

func (a *addressFamily) Router() netip.Addr {
	return a.router
}

func (a *addressFamily) PrimaryExternal() netip.Addr {
	return a.primaryExternal
}

func (a *addressFamily) AllocationCIDR() netip.Prefix {
	return a.allocCIDR
}

func (a *addressFamily) DirectRouting() (int, net.IP, bool) {
	return 0, nil, false
}

func (n *nodeAddressing) IPv6() node.AddressingFamily {
	return &n.ipv6
}

func (n *nodeAddressing) IPv4() node.AddressingFamily {
	return &n.ipv4
}
