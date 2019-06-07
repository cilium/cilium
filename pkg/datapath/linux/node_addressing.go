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

package linux

import (
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/node"

	"github.com/vishvananda/netlink"
)

// FIXME: This currently maps to the code in pkg/node/node_address.go. That
// code should really move into this package.

func listLocalAddresses(family int) ([]net.IP, error) {
	addrs, err := netlink.AddrList(nil, family)
	if err != nil {
		return nil, err
	}

	var addresses []net.IP

	for _, addr := range addrs {
		if addr.Scope == int(netlink.SCOPE_LINK) {
			continue
		}

		switch addr.IP.String() {
		case "127.0.0.1", "::1":
			continue
		}

		addresses = append(addresses, addr.IP)
	}

	return addresses, nil
}

type addressFamilyIPv4 struct{}

func (a *addressFamilyIPv4) Router() net.IP {
	return node.GetInternalIPv4()
}

func (a *addressFamilyIPv4) PrimaryExternal() net.IP {
	return node.GetExternalIPv4()
}

func (a *addressFamilyIPv4) AllocationCIDR() *cidr.CIDR {
	return node.GetIPv4AllocRange()
}

func (a *addressFamilyIPv4) LocalAddresses() ([]net.IP, error) {
	return listLocalAddresses(netlink.FAMILY_V4)
}

type addressFamilyIPv6 struct{}

func (a *addressFamilyIPv6) Router() net.IP {
	return node.GetIPv6Router()
}

func (a *addressFamilyIPv6) PrimaryExternal() net.IP {
	return node.GetIPv6()
}

func (a *addressFamilyIPv6) AllocationCIDR() *cidr.CIDR {
	return node.GetIPv6AllocRange()
}

func (a *addressFamilyIPv6) LocalAddresses() ([]net.IP, error) {
	return listLocalAddresses(netlink.FAMILY_V6)
}

type linuxNodeAddressing struct {
	ipv6 addressFamilyIPv6
	ipv4 addressFamilyIPv4
}

// NewNodeAddressing returns a new linux node addressing model
func NewNodeAddressing() datapath.NodeAddressing {
	return &linuxNodeAddressing{}
}

func (n *linuxNodeAddressing) IPv6() datapath.NodeAddressingFamily {
	return &n.ipv6
}

func (n *linuxNodeAddressing) IPv4() datapath.NodeAddressingFamily {
	return &n.ipv4
}
