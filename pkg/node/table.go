// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"net"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/node/types"
)

const (
	NodesTableName = "nodes"
)

var (
	NodeIdentityIndex = statedb.Index[*types.Node, types.Identity]{
		Name: "name",
		FromObject: func(node *types.Node) index.KeySet {
			return index.NewKeySet(index.String(node.GetKeyName()))
		},
		FromKey: func(id types.Identity) index.Key {
			return index.String(types.GetKeyNodeName(id.Cluster, id.Name))
		},
		Unique: true,
	}

	NodeIPIndex = statedb.Index[*types.Node, net.IP]{
		Name: "ip",
		FromObject: func(node *types.Node) index.KeySet {
			ipv4 := node.GetNodeIP(false)
			ipv6 := node.GetNodeIP(true)
			switch {
			case ipv4 != nil && ipv6 != nil:
				return index.NewKeySet(index.NetIP(ipv4), index.NetIP(ipv6))
			case ipv4 != nil:
				return index.NewKeySet(index.NetIP(ipv4))
			case ipv6 != nil:
				return index.NewKeySet(index.NetIP(ipv6))
			default:
				return index.NewKeySet()
			}
		},
		FromKey: index.NetIP,
		Unique:  true,
	}

	NodeLocalIndex = statedb.Index[*types.Node, bool]{
		Name: "local",
		FromObject: func(node *types.Node) index.KeySet {
			return index.NewKeySet(index.Bool(node.IsLocal()))
		},
		FromKey: index.Bool,
		Unique:  true,
	}
)

func NewNodesTable(db *statedb.DB) (statedb.RWTable[*types.Node], error) {
	tbl, err := statedb.NewTable(
		NodesTableName,
		NodeIdentityIndex,
		NodeIPIndex,
		NodeLocalIndex,
	)
	if err == nil {
		err = db.RegisterTable(tbl)
	}
	return tbl, err
}
