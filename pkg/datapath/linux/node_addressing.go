// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/vishvananda/netlink"
)

/* FIXME make sure devices table captures the peculiarities here
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
}*/

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

func (a *addressFamilyIPv4) Router() net.IP {
	n, _ := a.localNode.Get(context.TODO())
	return n.GetCiliumInternalIP(false)
}

func (a *addressFamilyIPv4) PrimaryExternal() net.IP {
	n, _ := a.localNode.Get(context.TODO())
	return n.GetNodeIP(false)
}

func (a *addressFamilyIPv4) AllocationCIDR() *cidr.CIDR {
	n, _ := a.localNode.Get(context.TODO())
	return n.IPv4AllocCIDR
}

func (a *addressFamilyIPv4) LocalAddresses() (addrs []net.IP, err error) {
	devs, _ := tables.SelectedDevices(a.devicesTable, a.db.ReadTxn())
	for _, dev := range devs {
		for _, addr := range dev.Addrs {
			// TODO: Filter by scope?
			if addr.Addr.Is4() {
				addrs = append(addrs, addr.AsIP())
			}
		}
	}
	return addrs, nil
}

// LoadBalancerNodeAddresses returns all IPv4 node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a *addressFamilyIPv4) LoadBalancerNodeAddresses() (addrs []net.IP) {
	addrs, _ = a.LocalAddresses()
	addrs = append(addrs, net.IPv4zero)
	return addrs
}

func (a *addressFamilyIPv6) Router() net.IP {
	n, _ := a.localNode.Get(context.TODO())
	return n.GetCiliumInternalIP(true)
}

func (a *addressFamilyIPv6) PrimaryExternal() net.IP {
	n, _ := a.localNode.Get(context.TODO())
	return n.GetNodeIP(true)
}

func (a *addressFamilyIPv6) AllocationCIDR() *cidr.CIDR {
	n, _ := a.localNode.Get(context.TODO())
	return n.IPv6AllocCIDR
}

func (a *addressFamilyIPv6) LocalAddresses() (addrs []net.IP, err error) {
	devs, _ := tables.SelectedDevices(a.devicesTable, a.db.ReadTxn())
	for _, dev := range devs {
		for _, addr := range dev.Addrs {
			if addr.Addr.Is6() {
				addrs = append(addrs, addr.AsIP())
			}
		}
	}
	return addrs, nil
}

// LoadBalancerNodeAddresses returns all IPv6 node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a *addressFamilyIPv6) LoadBalancerNodeAddresses() (addrs []net.IP) {
	addrs, _ = a.LocalAddresses()
	addrs = append(addrs, net.IPv6zero)
	return addrs
}

type linuxNodeAddressing struct {
	localNode    *node.LocalNodeStore
	db           *statedb.DB
	devicesTable statedb.Table[*tables.Device]
}

type addressFamilyIPv4 linuxNodeAddressing
type addressFamilyIPv6 linuxNodeAddressing

// NewNodeAddressing returns a new linux node addressing model
func NewNodeAddressing(localNode *node.LocalNodeStore, db *statedb.DB, devicesTable statedb.Table[*tables.Device]) types.NodeAddressing {
	return &linuxNodeAddressing{localNode: localNode, db: db, devicesTable: devicesTable}
}

func (n *linuxNodeAddressing) IPv6() types.NodeAddressingFamily {
	return (*addressFamilyIPv4)(n)
}

func (n *linuxNodeAddressing) IPv4() types.NodeAddressingFamily {
	return (*addressFamilyIPv6)(n)
}
