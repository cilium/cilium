// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/statedb"
)

var NodeAddressingCell = cell.Module(
	"node-addressing",
	"Accessors for looking up local node IP addresses",

	cell.Provide(NewNodeAddressing),
)

func NewNodeAddressing(localNode *node.LocalNodeStore, db *statedb.DB, nodeAddresses statedb.Table[NodeAddress], devices statedb.Table[*Device]) types.NodeAddressing {
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
	return a.getNodeAddresses(a.db.ReadTxn(), ipv4), nil
}

// LoadBalancerNodeAddresses returns all IPv4 node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a addressFamilyIPv4) LoadBalancerNodeAddresses() []net.IP {
	addrs := a.getNodeAddresses(a.db.ReadTxn(), ipv4|nodePort)
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
	return a.getNodeAddresses(a.db.ReadTxn(), ipv6), nil
}

// LoadBalancerNodeAddresses returns all IPv6 node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a addressFamilyIPv6) LoadBalancerNodeAddresses() []net.IP {
	addrs := a.getNodeAddresses(a.db.ReadTxn(), ipv6|nodePort)
	addrs = append(addrs, net.IPv6zero)

	return addrs
}

type nodeAddressing struct {
	localNode     *node.LocalNodeStore
	db            *statedb.DB
	nodeAddresses statedb.Table[NodeAddress]
	devices       statedb.Table[*Device]
}

type getFlag int

const (
	ipv4     getFlag = 1 << 0
	ipv6     getFlag = 1 << 1
	nodePort getFlag = 1 << 2
)

func (na *nodeAddressing) getNodeAddresses(txn statedb.ReadTxn, flag getFlag) (addrs []net.IP) {
	nodeAddrs, _ := na.nodeAddresses.All(txn)
	for addr, _, ok := nodeAddrs.Next(); ok; addr, _, ok = nodeAddrs.Next() {
		if flag&nodePort != 0 && !addr.NodePort {
			continue
		}
		if flag&ipv4 != 0 && addr.Addr.Is4() {
			addrs = append(addrs, addr.IP())
		} else if flag&ipv6 != 0 && addr.Addr.Is6() {
			addrs = append(addrs, addr.IP())
		}
	}
	return
}

type addressFamilyIPv4 struct{ *nodeAddressing }
type addressFamilyIPv6 struct{ *nodeAddressing }

func (n *nodeAddressing) IPv6() types.NodeAddressingFamily {
	return addressFamilyIPv6{n}
}

func (n *nodeAddressing) IPv4() types.NodeAddressingFamily {
	return addressFamilyIPv4{n}
}
