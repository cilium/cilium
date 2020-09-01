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

package linux

import (
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node"

	"github.com/vishvananda/netlink"
)

func mapLocalAddresses(family int, f func(ip net.IP) error) error {
	ipsToExclude := node.GetExcludedIPs()
	addrs, err := netlink.AddrList(nil, family)
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		if addr.Scope == int(netlink.SCOPE_LINK) {
			continue
		}
		if ip.IsExcluded(ipsToExclude, addr.IP) {
			continue
		}
		if addr.IP.IsLoopback() {
			continue
		}
		err = f(addr.IP)
		if err != nil {
			return err
		}
	}

	if hostDevice, err := netlink.LinkByName(defaults.HostDevice); hostDevice != nil && err == nil {
		addrs, err = netlink.AddrList(hostDevice, family)
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			if addr.Scope == int(netlink.SCOPE_LINK) {
				err = f(addr.IP)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func mapSubnetAddresses(nets []net.IPNet, f func(ip net.IP) error) error {
	for _, nt := range nets {
		for addr := nt.IP.Mask(nt.Mask); nt.Contains(addr); addr = ip.GetNextIP(addr) {
			err := f(addr)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type addressFamilyIPv4 struct {
	subnetOverride []net.IPNet
}

func (a *addressFamilyIPv4) Router() net.IP {
	return node.GetInternalIPv4()
}

func (a *addressFamilyIPv4) PrimaryExternal() net.IP {
	return node.GetExternalIPv4()
}

func (a *addressFamilyIPv4) AllocationCIDR() *cidr.CIDR {
	return node.GetIPv4AllocRange()
}

func (a *addressFamilyIPv4) MapLocalAddresses(f func(ip net.IP) error) error {
	if len(a.subnetOverride) > 0 {
		return mapSubnetAddresses(a.subnetOverride, f)
	}
	return mapLocalAddresses(netlink.FAMILY_V4, f)
}

func (a *addressFamilyIPv4) SubnetOverride() []net.IPNet {
	return a.subnetOverride
}

// LoadBalancerNodeAddresses returns all IPv4 node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a *addressFamilyIPv4) LoadBalancerNodeAddresses() []net.IP {
	addrs := node.GetNodePortIPv4Addrs()
	addrs = append(addrs, net.IPv4zero)
	return addrs
}

type addressFamilyIPv6 struct {
	subnetOverride []net.IPNet
}

func (a *addressFamilyIPv6) Router() net.IP {
	return node.GetIPv6Router()
}

func (a *addressFamilyIPv6) PrimaryExternal() net.IP {
	return node.GetIPv6()
}

func (a *addressFamilyIPv6) AllocationCIDR() *cidr.CIDR {
	return node.GetIPv6AllocRange()
}

func (a *addressFamilyIPv6) MapLocalAddresses(f func(ip net.IP) error) error {
	if len(a.subnetOverride) > 0 {
		return mapSubnetAddresses(a.subnetOverride, f)
	}
	return mapLocalAddresses(netlink.FAMILY_V6, f)
}

func (a *addressFamilyIPv6) SubnetOverride() []net.IPNet {
	return a.subnetOverride
}

// LoadBalancerNodeAddresses returns all IPv6 node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a *addressFamilyIPv6) LoadBalancerNodeAddresses() []net.IP {
	addrs := node.GetNodePortIPv6Addrs()
	addrs = append(addrs, net.IPv6zero)
	return addrs
}

type linuxNodeAddressing struct {
	ipv6 addressFamilyIPv6
	ipv4 addressFamilyIPv4
}

// NewNodeAddressing returns a new linux node addressing model
func NewNodeAddressing(subnetOverrides []net.IPNet) datapath.NodeAddressing {
	var ipv4Nets []net.IPNet
	var ipv6Nets []net.IPNet
	for _, n := range subnetOverrides {
		if n.IP.To4() != nil {
			ipv4Nets = append(ipv4Nets, n)
		} else {
			ipv6Nets = append(ipv6Nets, n)
		}
	}
	return &linuxNodeAddressing{
		ipv6: addressFamilyIPv6{
			subnetOverride: ipv6Nets,
		},
		ipv4: addressFamilyIPv4{
			subnetOverride: ipv4Nets,
		},
	}
}

func (n *linuxNodeAddressing) IPv6() datapath.NodeAddressingFamily {
	return &n.ipv6
}

func (n *linuxNodeAddressing) IPv4() datapath.NodeAddressingFamily {
	return &n.ipv4
}
