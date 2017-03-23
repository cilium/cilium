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

package addressing

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

var (
	ErrIPv4Invalid         = errors.New("Invalid IPv4 address")
	ErrIPv4NotConfigured   = errors.New("No IPv4 address configured")
	ErrNodeIPEndpointIDSet = errors.New("Endpoint ID set in IPv6 node address")
	ErrNodeIDZero          = errors.New("Node ID is zero (invalid)")
)

type NodeAddress struct {
	IPv6Address CiliumIPv6
	IPv6Route   net.IPNet

	IPv4Address CiliumIPv4
	IPv4Route   net.IPNet
}

func (a *NodeAddress) String() string {
	return a.IPv6Address.String()
}

// NewNodeAddress allocate a new node address.
func NewNodeAddress(v6Address string, ipv4Range string, device string) (*NodeAddress, error) {
	v6, err := initIPv6Address(v6Address, device)
	if err != nil {
		return nil, err
	}

	v4, err := initIPv4Address(ipv4Range, device)
	if err != nil {
		return nil, err
	}

	return &NodeAddress{
		IPv6Address: v6,
		IPv6Route:   *v6.IPNet(128),
		IPv4Address: v4,
		IPv4Route:   *v4.IPNet(32),
	}, nil
}

func (a *NodeAddress) IPv4ClusterRange() *net.IPNet {
	mask := net.CIDRMask(DefaultIPv4ClusterPrefixLen, 32)

	return &net.IPNet{
		IP:   a.IPv4Address.IP().Mask(mask),
		Mask: mask,
	}
}

func (a *NodeAddress) IPv4AllocRange() *net.IPNet {
	mask := net.CIDRMask(DefaultIPv4PrefixLen, 32)

	return &net.IPNet{
		IP:   a.IPv4Address.IP().Mask(mask),
		Mask: mask,
	}
}

func (a *NodeAddress) IPv6AllocRange() *net.IPNet {
	mask := net.CIDRMask(DefaultIPv6PrefixLen, 128)

	return &net.IPNet{
		IP:   a.IPv6Address.IP().Mask(mask),
		Mask: mask,
	}
}

func firstGlobalV4Addr(intf string) (net.IP, error) {
	var link netlink.Link
	var err error

	if intf != "" && intf != "undefined" {
		link, err = netlink.LinkByName(intf)
		if err != nil {
			return firstGlobalV4Addr("")
		}
	}

	addr, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	for _, a := range addr {
		if a.Scope == syscall.RT_SCOPE_UNIVERSE {
			if len(a.IP) < 4 {
				return nil, ErrIPv4Invalid
			}

			return a.IP, nil
		}
	}

	return nil, ErrIPv4NotConfigured
}

func initIPv6Address(address string, device string) (CiliumIPv6, error) {
	if address == "" {
		address = DefaultIPv6Prefix
	}

	addressIP, err := NewCiliumIPv6(address)
	if err != nil {
		return nil, err
	}

	if addressIP.EndpointID() != 0 {
		return nil, ErrNodeIPEndpointIDSet
	}

	// If address is not specified, try and generate it from a public IPv4
	// address configured on the system
	if addressIP.NodeID() == 0 {
		ip, err := firstGlobalV4Addr(device)
		if err != nil {
			return nil, err
		}

		address = fmt.Sprintf("%s%02x%02x:%02x%02x:0:0",
			addressIP.String(), ip[0], ip[1], ip[2], ip[3])

		return NewCiliumIPv6(address)
	}

	return addressIP, nil
}

func initIPv4Address(v4range string, device string) (CiliumIPv4, error) {
	if v4range == "" {
		ip, err := firstGlobalV4Addr(device)
		if err != nil {
			return nil, err
		}

		v4range = fmt.Sprintf(DefaultIPv4Prefix, ip.To4()[3])
	}

	addressIP, err := NewCiliumIPv4(v4range)
	if err != nil {
		return nil, err
	}

	// The IPv4 prefix must contain a valid node address, unlike for IPv6,
	// the container-id bits cannot be zero.
	if addressIP.EndpointID() == 0 {
		return nil, ErrIPv4Invalid
	}

	if addressIP.NodeID() == 0 {
		return nil, ErrNodeIDZero
	}

	return addressIP, nil
}
