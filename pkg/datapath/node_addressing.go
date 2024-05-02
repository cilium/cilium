// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"context"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/node"
)

// NodeAddressingCell provides the [NodeAddressing] interface that provides
// access to local node addressing information. This will be eventually
// superceded by Table[NodeAddress].
var NodeAddressingCell = cell.Module(
	"node-addressing",
	"Accessors for looking up local node IP addresses",

	cell.Provide(NewNodeAddressing),
)

func NewNodeAddressing(localNode *node.LocalNodeStore, db *statedb.DB, devices statedb.Table[*tables.Device]) types.NodeAddressing {
	return &nodeAddressing{
		localNode: localNode,
		db:        db,
		devices:   devices,
	}
}

type nodeAddressing struct {
	localNode *node.LocalNodeStore
	db        *statedb.DB
	devices   statedb.Table[*tables.Device]
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

type getFlags int

const (
	ipv4     getFlags = 1 << 0
	ipv6     getFlags = 1 << 1
	nodePort getFlags = 1 << 2
)

type addressFamily struct {
	*nodeAddressing
	flags getFlags
}
