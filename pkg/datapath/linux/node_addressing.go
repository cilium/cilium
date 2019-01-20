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
)

// FIXME: This currently maps to the code in pkg/node/node_address.go. That
// code should really move into this package.

type addressFamilyIPv4 struct{}

func (a *addressFamilyIPv4) Router() net.IP {
	return node.GetInternalIPv4()
}

func (a *addressFamilyIPv4) PrimaryExternal() net.IP {
	return node.GetExternalIPv4()
}

func (a *addressFamilyIPv4) AllocationCIDR() *cidr.CIDR {
	return cidr.NewCIDR(node.GetIPv4AllocRange())
}

type addressFamilyIPv6 struct{}

func (a *addressFamilyIPv6) Router() net.IP {
	return node.GetIPv6Router()
}

func (a *addressFamilyIPv6) PrimaryExternal() net.IP {
	return node.GetIPv6()
}

func (a *addressFamilyIPv6) AllocationCIDR() *cidr.CIDR {
	return cidr.NewCIDR(node.GetIPv6AllocRange())
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
