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

package nodeaddress

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/cilium/common/addressing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	ErrIPv4Invalid         = errors.New("Invalid IPv4 address")
	ErrIPv4NotConfigured   = errors.New("No IPv4 address configured")
	ErrNodeIPEndpointIDSet = errors.New("Endpoint ID set in IPv6 node address")
	ErrNodeIDZero          = errors.New("Node ID is zero (invalid)")

	// IPv6Address is the IPv6 address of the node
	IPv6Address addressing.CiliumIPv6

	// IPv6Route is the /128 route for the node address
	IPv6Route net.IPNet

	// IPv4Address is the IPv4 address of the node
	IPv4Address addressing.CiliumIPv4

	// IPv4Route is the /32 route for the node address
	IPv4Route net.IPNet
)

// SetNodeAddress sets the node's IPv4 and IPv6 address. Multiple calls to this
// function will overwrite the node address.
func SetNodeAddress(v6Address string, ipv4Range string, device string) error {
	v6, err := initIPv6Address(v6Address, device)
	if err != nil {
		return err
	}

	v4, err := initIPv4Address(ipv4Range, device)
	if err != nil {
		return err
	}

	IPv6Address = v6
	IPv6Route = *v6.IPNet(128)
	IPv4Address = v4
	IPv4Route = *v4.IPNet(32)

	return nil
}

// IPv4ClusterRange returns the IPv4 prefix of the cluster
func IPv4ClusterRange() *net.IPNet {
	mask := net.CIDRMask(DefaultIPv4ClusterPrefixLen, 32)

	return &net.IPNet{
		IP:   IPv4Address.IP().Mask(mask),
		Mask: mask,
	}
}

// IPv4AllocRange returns the IPv4 allocation prefix of this node
func IPv4AllocRange() *net.IPNet {
	mask := net.CIDRMask(DefaultIPv4PrefixLen, 32)

	return &net.IPNet{
		IP:   IPv4Address.IP().Mask(mask),
		Mask: mask,
	}
}

// IPv6ClusterRange returns the IPv6 prefix of the clustr
func IPv6ClusterRange() *net.IPNet {
	mask := net.CIDRMask(DefaultIPv6ClusterPrefixLen, 128)

	return &net.IPNet{
		IP:   IPv6Address.IP().Mask(mask),
		Mask: mask,
	}
}

// IPv6AllocRange returns the IPv6 allocation prefix of this node
func IPv6AllocRange() *net.IPNet {
	mask := net.CIDRMask(DefaultIPv6PrefixLen, 128)

	return &net.IPNet{
		IP:   IPv6Address.IP().Mask(mask),
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
		if a.Scope == unix.RT_SCOPE_UNIVERSE {
			if len(a.IP) < 4 {
				return nil, ErrIPv4Invalid
			}

			return a.IP, nil
		}
	}

	return nil, ErrIPv4NotConfigured
}

func initIPv6Address(address string, device string) (addressing.CiliumIPv6, error) {
	if address == "" {
		address = DefaultIPv6Prefix
	}

	addressIP, err := addressing.NewCiliumIPv6(address)
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

		return addressing.NewCiliumIPv6(address)
	}

	return addressIP, nil
}

func initIPv4Address(v4range string, device string) (addressing.CiliumIPv4, error) {
	if v4range == "" {
		ip, err := firstGlobalV4Addr(device)
		if err != nil {
			return nil, err
		}

		v4range = fmt.Sprintf(DefaultIPv4Prefix, ip.To4()[3])
	}

	addressIP, err := addressing.NewCiliumIPv4(v4range)
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
