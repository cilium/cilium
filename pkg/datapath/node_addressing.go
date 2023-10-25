// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"context"
	"net"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
)

var NodeAddressingCell = cell.Module(
	"node-addressing",
	"Accessors for looking up node IP address information",

	cell.Provide(NewNodeAddressing),
)

func NewNodeAddressing(localNode *node.LocalNodeStore, db *statedb.DB, nodeAddresses statedb.Table[tables.NodeAddress], devices statedb.Table[*tables.Device]) types.NodeAddressing {
	return &nodeAddressing{
		localNode:     localNode,
		db:            db,
		nodeAddresses: nodeAddresses,
		devices:       devices,
	}
}

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
	addrs := a.getNodeAddresses(a.db.ReadTxn(), false)
	addrs = append(addrs, net.IPv4zero)
	return addrs
}

func (a addressFamilyIPv4) DirectRouting() (int, net.IP, bool) {
	return a.directRouting(false)
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
	addrs := a.getNodeAddresses(a.db.ReadTxn(), true)
	addrs = append(addrs, net.IPv6zero)
	return addrs
}

func (a addressFamilyIPv6) DirectRouting() (int, net.IP, bool) {
	return a.directRouting(true)
}

type nodeAddressing struct {
	localNode     *node.LocalNodeStore
	db            *statedb.DB
	nodeAddresses statedb.Table[tables.NodeAddress]
	devices       statedb.Table[*tables.Device]
}

func (na *nodeAddressing) getNodeAddresses(txn statedb.ReadTxn, ipv6 bool) (addrs []net.IP) {
	nodeAddrs, _ := na.nodeAddresses.All(txn)
	for addr, _, ok := nodeAddrs.Next(); ok; addr, _, ok = nodeAddrs.Next() {
		if ipv6 && addr.Addr.Is4() {
			continue
		}
		if !ipv6 && !addr.Addr.Is4() {
			continue
		}
		addrs = append(addrs, addr.IP())
	}
	return
}

func (na *nodeAddressing) getLocalAddresses(txn statedb.ReadTxn, ipv6 bool) (addrs []net.IP, err error) {
	// Collect the addresses of native external-facing network devices
	addrs = na.getNodeAddresses(txn, ipv6)

	// If AddressScopeMax is a scope more broad (numerically less than) than SCOPE_LINK then include
	// all addresses at SCOPE_LINK which are assigned to the Cilium host device.
	if option.Config.AddressScopeMax < unix.RT_SCOPE_LINK && na.devices != nil {
		hostDev, _, ok := na.devices.First(txn, tables.DeviceNameIndex.Query(defaults.HostDevice))
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

func (na *nodeAddressing) directRouting(ipv6 bool) (int, net.IP, bool) {
	deviceName := option.Config.DirectRoutingDevice
	if deviceName == "" {
		return 0, nil, false
	}
	dev, _, ok := na.devices.First(na.db.ReadTxn(), tables.DeviceNameIndex.Query(option.Config.DirectRoutingDevice))
	if !ok {
		return 0, nil, false
	}
	var addr net.IP
	for _, a := range dev.Addrs {
		if ipv6 && a.Addr.Is6() {
			addr = a.AsIP()
			break
		} else if !ipv6 && a.Addr.Is4() {
			addr = a.AsIP()
			break
		}
	}
	return dev.Index, addr, true
}

type addressFamilyIPv4 struct{ *nodeAddressing }
type addressFamilyIPv6 struct{ *nodeAddressing }

func (n *nodeAddressing) IPv6() types.NodeAddressingFamily {
	return addressFamilyIPv6{n}
}

func (n *nodeAddressing) IPv4() types.NodeAddressingFamily {
	return addressFamilyIPv4{n}
}
