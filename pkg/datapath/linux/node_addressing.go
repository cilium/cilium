// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// FIXME: This currently maps to the code in pkg/node/node_address.go. That
// code should really move into this package.

func listLocalAddresses(family int) ([]net.IP, error) {
	var addresses []net.IP

	ipsToExclude := node.GetExcludedIPs()
	addrs, err := netlink.AddrList(nil, family)
	if err != nil {
		return nil, err
	}

	filteredIPs := filterLocalAddresses(addrs, ipsToExclude, option.Config.AddressScopeMax)
	addresses = append(addresses, filteredIPs...)

	// If AddressScopeMax is a scope more broad (numerically less than) than SCOPE_LINK then include
	// all addresses at SCOPE_LINK which are assigned to the Cilium host device.
	if option.Config.AddressScopeMax < int(netlink.SCOPE_LINK) {
		if hostDevice, err := netlink.LinkByName(defaults.HostDevice); hostDevice != nil && err == nil {
			addrs, err = netlink.AddrList(hostDevice, family)
			if err != nil {
				return nil, err
			}
			for _, addr := range addrs {
				if addr.Scope == int(netlink.SCOPE_LINK) {
					addresses = append(addresses, addr.IP)
				}
			}
		}
	}

	return addresses, nil
}

func filterLocalAddresses(addrs []netlink.Addr, ipsToExclude []net.IP, addrScopeMax int) []net.IP {
	var filteredIPs []net.IP
	for _, addr := range addrs {
		// This address is at a scope which is more narrow (numerically greater than) the configured
		// max address scope. For example, if this addr is SCOPE_NOWHERE, and our addrScopeMax is
		// SCOPE_LINK, then we do NOT treat the address as a local address. Similarly, if this addr
		// is SCOPE_HOST, and our addrScopeMax is SCOPE_LINK, we do NOT treat the address as a local
		// address.
		if addr.Scope > addrScopeMax {
			continue
		}
		if ip.ListContainsIP(ipsToExclude, addr.IP) {
			continue
		}
		if addr.IP.IsLoopback() {
			continue
		}
		filteredIPs = append(filteredIPs, addr.IP)
	}
	return filteredIPs
}

type addressFamilyIPv4 struct{}

func (a *addressFamilyIPv4) Router() net.IP {
	return node.GetInternalIPv4Router()
}

func (a *addressFamilyIPv4) PrimaryExternal() net.IP {
	return node.GetIPv4()
}

func (a *addressFamilyIPv4) AllocationCIDR() *cidr.CIDR {
	return node.GetIPv4AllocRange()
}

func (a *addressFamilyIPv4) LocalAddresses() ([]net.IP, error) {
	addrs, err := listLocalAddresses(netlink.FAMILY_V4)

	if err != nil {
		return nil, err
	}

	if externalAddress := node.GetK8sExternalIPv4(); externalAddress != nil {
		addrs = append(addrs, externalAddress)
	}

	return addrs, nil
}

// LoadBalancerNodeAddresses returns all IPv4 node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a *addressFamilyIPv4) LoadBalancerNodeAddresses() []net.IP {
	addrs := node.GetNodePortIPv4Addrs()
	addrs = append(addrs, net.IPv4zero)
	return addrs
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
	addrs, err := listLocalAddresses(netlink.FAMILY_V6)

	if err != nil {
		return nil, err
	}

	if externalAddress := node.GetK8sExternalIPv6(); externalAddress != nil {
		addrs = append(addrs, externalAddress)
	}

	return addrs, nil
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
func NewNodeAddressing() types.NodeAddressing {
	return &linuxNodeAddressing{}
}

func (n *linuxNodeAddressing) IPv6() types.NodeAddressingFamily {
	return &n.ipv6
}

func (n *linuxNodeAddressing) IPv4() types.NodeAddressingFamily {
	return &n.ipv4
}
