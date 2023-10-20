// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"context"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
	"golang.org/x/sys/unix"
)

func (a addressFamilyIPv4) Router() net.IP {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.GetCiliumInternalIP(false)
	}
	return nil
}

func (a addressFamilyIPv4) PrimaryExternal() net.IP {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.GetNodeIP(false)
	}
	return nil
}

func (a addressFamilyIPv4) AllocationCIDR() *cidr.CIDR {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.IPv4AllocCIDR
	}
	return nil
}

func (a addressFamilyIPv4) LocalAddresses() (addrs []net.IP, err error) {
	return a.getLocalAddresses(a.db.ReadTxn(), false)
}

// LoadBalancerNodeAddresses returns all IPv4 node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a addressFamilyIPv4) LoadBalancerNodeAddresses() []net.IP {
	addrs := a.getExternalAddresses(a.db.ReadTxn(), false)
	addrs = append(addrs, net.IPv4zero)
	return addrs
}

func (a addressFamilyIPv6) Router() net.IP {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.GetCiliumInternalIP(true)
	}
	return nil
}

func (a addressFamilyIPv6) PrimaryExternal() net.IP {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.GetNodeIP(true)
	}
	return nil
}

func (a addressFamilyIPv6) AllocationCIDR() *cidr.CIDR {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.IPv6AllocCIDR
	}
	return nil
}

func (a addressFamilyIPv6) LocalAddresses() ([]net.IP, error) {
	return a.getLocalAddresses(a.db.ReadTxn(), true)
}

// LoadBalancerNodeAddresses returns all IPv6 node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a addressFamilyIPv6) LoadBalancerNodeAddresses() []net.IP {
	addrs := a.getExternalAddresses(a.db.ReadTxn(), true)
	addrs = append(addrs, net.IPv6zero)
	return addrs
}

type linuxNodeAddressing struct {
	localNode    *node.LocalNodeStore
	db           *statedb.DB
	devicesTable statedb.Table[*tables.Device]
}

func (na *linuxNodeAddressing) getExternalAddresses(txn statedb.ReadTxn, ipv6 bool) (addrs []net.IP) {
	nativeDevs, _ := tables.SelectedDevices(na.devicesTable, txn)
	for _, dev := range nativeDevs {
		for _, addr := range dev.Addrs {
			if ipv6 && addr.Addr.Is4() {
				continue
			}
			if !ipv6 && !addr.Addr.Is4() {
				continue
			}
			addrs = append(addrs, addr.AsIP())
		}
	}
	return
}

func (na *linuxNodeAddressing) getLocalAddresses(txn statedb.ReadTxn, ipv6 bool) (addrs []net.IP, err error) {
	// Collect the addresses of native external-facing network devices
	addrs = na.getExternalAddresses(txn, ipv6)

	// If AddressScopeMax is a scope more broad (numerically less than) than SCOPE_LINK then include
	// all addresses at SCOPE_LINK which are assigned to the Cilium host device.
	if option.Config.AddressScopeMax < unix.RT_SCOPE_LINK {
		hostDev, _, ok := na.devicesTable.First(txn, tables.DeviceNameIndex.Query(defaults.HostDevice))
		if ok {
			for _, addr := range hostDev.Addrs {
				if addr.Scope != unix.RT_SCOPE_LINK {
					continue
				}
				if ipv6 && addr.Addr.Is4() {
					continue
				}
				if !ipv6 && !addr.Addr.Is4() {
					continue
				}
				addrs = append(addrs, addr.AsIP())
			}
		}
	}
	return addrs, nil
}

type addressFamilyIPv4 struct{ *linuxNodeAddressing }
type addressFamilyIPv6 struct{ *linuxNodeAddressing }

// NewNodeAddressing returns a new linux node addressing model
func NewNodeAddressing(localNode *node.LocalNodeStore, db *statedb.DB, devicesTable statedb.Table[*tables.Device]) types.NodeAddressing {
	return &linuxNodeAddressing{localNode: localNode, db: db, devicesTable: devicesTable}
}

func (n *linuxNodeAddressing) IPv6() types.NodeAddressingFamily {
	return addressFamilyIPv6{n}
}

func (n *linuxNodeAddressing) IPv4() types.NodeAddressingFamily {
	return addressFamilyIPv4{n}
}
