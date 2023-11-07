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
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
)

// NodeAddressingCell provides the [NodeAddressing] interface that provides
// access to local node addressing information. This will be eventually
// superceded by Table[NodeAddress].
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

type nodeAddressing struct {
	localNode     *node.LocalNodeStore
	db            *statedb.DB
	nodeAddresses statedb.Table[NodeAddress]
	devices       statedb.Table[*Device]
}

func (n *nodeAddressing) IPv6() types.NodeAddressingFamily {
	return addressFamily{n, ipv6}
}

func (n *nodeAddressing) IPv4() types.NodeAddressingFamily {
	return addressFamily{n, ipv4}
}

func (a addressFamily) Router() net.IP {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.GetCiliumInternalIP(a.flags&ipv6 != 0)
	}
	return nil
}

func (a addressFamily) PrimaryExternal() net.IP {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.GetNodeIP(a.flags&ipv6 != 0)
	}
	return nil
}

func (a addressFamily) AllocationCIDR() *cidr.CIDR {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		if a.flags&ipv6 != 0 {
			return n.IPv6AllocCIDR
		} else {
			return n.IPv4AllocCIDR
		}
	}
	return nil
}

func (a addressFamily) LocalAddresses() (addrs []net.IP, err error) {
	return a.getNodeAddresses(a.db.ReadTxn(), a.flags), nil
}

func (a addressFamily) DirectRouting() (int, net.IP, bool) {
	return a.getDirectRouting(a.flags)
}

// LoadBalancerNodeAddresses returns all node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a addressFamily) LoadBalancerNodeAddresses() []net.IP {
	addrs := a.getNodeAddresses(a.db.ReadTxn(), a.flags|nodePort)
	if a.flags&ipv6 != 0 {
		addrs = append(addrs, net.IPv6zero)
	} else {
		addrs = append(addrs, net.IPv4zero)
	}
	return addrs
}

type getFlags int

const (
	ipv4     getFlags = 1 << 0
	ipv6     getFlags = 1 << 1
	nodePort getFlags = 1 << 2
)

func (a addressFamily) getDirectRouting(flags getFlags) (int, net.IP, bool) {
	if option.Config.DirectRoutingDevice == "" {
		return 0, nil, false
	}
	dev, _, ok := a.devices.First(a.db.ReadTxn(), DeviceNameIndex.Query(option.Config.DirectRoutingDevice))
	if !ok {
		return 0, nil, false
	}
	var addr net.IP
	for _, a := range dev.Addrs {
		if flags&ipv6 != 0 && a.Addr.Is6() {
			addr = a.AsIP()
			break
		} else if flags&ipv6 == 0 && a.Addr.Is4() {
			addr = a.AsIP()
			break
		}
	}
	return dev.Index, addr, true
}

func (a addressFamily) getNodeAddresses(txn statedb.ReadTxn, flag getFlags) (addrs []net.IP) {
	nodeAddrs, _ := a.nodeAddresses.All(txn)
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

type addressFamily struct {
	*nodeAddressing
	flags getFlags
}
