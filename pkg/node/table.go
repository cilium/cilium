// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"net"
	"slices"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/node/types"
)

type LocalNode = Node

// Node is a Cilium node. It is the local node if [Node.Local] is non-nil.
//
// +k8s:deepcopy-gen=true
// +deepequal-gen=true
type Node struct {
	types.Node

	// Local is non-nil if this is the local node. This carries additional
	// information about the local node that is not shared outside.
	Local *LocalNodeInfo
}

// TableHeader implements statedb.TableWritable.
func (n *Node) TableHeader() []string {
	return []string{
		"Name",
		"Source",
		"Addresses",
	}
}

// TableRow implements statedb.TableWritable.
func (n *Node) TableRow() []string {
	addrs := make([]string, len(n.IPAddresses))
	for i := range n.IPAddresses {
		addrs[i] = string(n.IPAddresses[i].Type) + ":" + n.IPAddresses[i].ToString()
	}
	slices.Sort(addrs)
	return []string{
		n.Fullname(),
		string(n.Source),
		strings.Join(addrs, ", "),
	}
}

var _ statedb.TableWritable = &Node{}

// LocalNodeInfo is the additional information about the local node that
// is only used internally.
//
// +k8s:deepcopy-gen=true
// +deepequal-gen=true
type LocalNodeInfo struct {
	// OptOutNodeEncryption will make the local node opt-out of node-to-node
	// encryption
	OptOutNodeEncryption bool
	// Unique identifier of the Kubernetes node, used to construct the
	// corresponding owner reference.
	UID k8stypes.UID
	// ID of the node assigned by the cloud provider.
	ProviderID string
	// v4 CIDR in which pod IPs are routable
	IPv4NativeRoutingCIDR *cidr.CIDR
	// v6 CIDR in which pod IPs are routable
	IPv6NativeRoutingCIDR *cidr.CIDR
	// ServiceLoopbackIPv4 is the source address used for SNAT when a Pod talks to
	// itself through a Service.
	ServiceLoopbackIPv4 net.IP
	// IsBeingDeleted indicates that the local node is being deleted.
	IsBeingDeleted bool
	// UnderlayProtocol is the IP family of our underlay.
	UnderlayProtocol tunnel.UnderlayProtocol
}

const (
	NodeTableName = "nodes"
)

var (
	NodeNameIndex = statedb.Index[*LocalNode, string]{
		Name: "name",
		FromObject: func(obj *LocalNode) index.KeySet {
			return index.NewKeySet(index.String(obj.Fullname()))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
	NodeByName = NodeNameIndex.Query

	NodeLocalIndex = statedb.Index[*LocalNode, bool]{
		Name: "local",
		FromObject: func(obj *LocalNode) index.KeySet {
			if obj.Local == nil {
				// Don't add remote nodes to this index at all.
				return index.KeySet{}
			}
			return index.NewKeySet(index.Bool(true))
		},
		FromKey:    index.Bool,
		FromString: index.BoolString,
		Unique:     true,
	}

	NodeByLocal    = NodeLocalIndex.Query
	LocalNodeQuery = NodeByLocal(true)
)

func NewNodeTable(db *statedb.DB) (statedb.RWTable[*LocalNode], error) {
	return statedb.NewTable(
		db,
		NodeTableName,
		NodeNameIndex,
		NodeLocalIndex,
	)
}
