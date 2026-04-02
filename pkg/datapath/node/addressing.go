// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/node"
)

// AddressingCell provides the [node.Addressing] interface that provides access
// to local node addressing information. This will be eventually superseded by
// Table[NodeAddress].
var AddressingCell = cell.Module(
	"node-addressing",
	"Accessors for looking up local node IP addresses",

	cell.Provide(NewAddressing),
)

func NewAddressing(localNode *node.LocalNodeStore, db *statedb.DB, devices statedb.Table[*tables.Device]) node.Addressing {
	return &addressing{
		localNode: localNode,
		db:        db,
		devices:   devices,
	}
}

type addressing struct {
	localNode *node.LocalNodeStore
	db        *statedb.DB
	devices   statedb.Table[*tables.Device]
}

func (n *addressing) IPv6() node.AddressingFamily {
	return addressFamily{n, ipv6}
}

func (n *addressing) IPv4() node.AddressingFamily {
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
	ipv4 getFlags = 1 << 0
	ipv6 getFlags = 1 << 1
)

type addressFamily struct {
	*addressing
	flags getFlags
}
