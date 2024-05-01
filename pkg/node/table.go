// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"fmt"
	"net"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

const (
	TableName = "nodes"
)

type LocalNodeAttrs struct {
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
	// IPv4 loopback address
	IPv4Loopback net.IP
}

func (l *LocalNodeAttrs) Clone() *LocalNodeAttrs {
	if l == nil {
		return nil
	}
	l2 := *l
	return &l2
}

// Node is the accessor interface to node-related information.
// This is defined as an interface to ensure no mutation of the immutable node
// struct takes place. Only way to modify a node is via Builder() followed by an
// Insert().
type Node interface {
	Name() string
	Cluster() string
	Source() source.Source
	Identity() types.Identity

	// GetKeyName returns the unique key of the node:
	// <cluster>/<node name>
	GetKeyName() string

	GetNodeIP(ipv6 bool) net.IP

	// GetNode returns a shallow copy of the node struct. The node struct is the internal
	// model behind the interface and it is also used for marshalling the node to KVStore.
	Node() types.Node

	// Local returns the extra information carried for the local node. Nil if this
	// node is not the local node.
	Local() *LocalNodeAttrs

	IsLocal() bool

	Builder() *NodeBuilder

	TableHeader() []string
	TableRow() []string
}

type NodeBuilder struct {
	orig *tableNode
	new  *tableNode
}

func (b *NodeBuilder) Build() (Node, error) {
	if !source.AllowOverwrite(b.orig.Source(), b.new.Source()) {
		return nil, fmt.Errorf("source %q cannot overwrite %q", b.new.Source(), b.orig.Source())
	}
	// TODO add other validations here
	return b.new, nil
}

func (b *NodeBuilder) ModifyNode(mod func(n *types.Node)) *NodeBuilder {
	mod(&b.new.node)
	return b
}

func (b *NodeBuilder) ModifyLocal(mod func(l *LocalNodeAttrs)) *NodeBuilder {
	if b.new.local == nil {
		b.new.local = &LocalNodeAttrs{}
	}
	mod(b.new.local)
	return b
}

// tableNode is the concrete struct stored in the node table.
type tableNode struct {
	node  types.Node
	local *LocalNodeAttrs
}

func NewTableNode(n types.Node, l *LocalNodeAttrs) Node {
	return &tableNode{node: n, local: l}
}

func (n *tableNode) Builder() *NodeBuilder {
	return &NodeBuilder{
		orig: n,
		new: &tableNode{
			node:  *n.node.DeepCopy(),
			local: n.local.Clone(),
		},
	}
}

func (n *tableNode) Name() string {
	return n.node.Name
}

func (n *tableNode) Source() source.Source {
	return n.node.Source
}

func (n *tableNode) Identity() types.Identity {
	return n.node.Identity()
}

// Cluster implements Node.
func (n *tableNode) Cluster() string {
	return n.node.Cluster
}

// GetKeyName implements Node.
func (n *tableNode) GetKeyName() string {
	return n.node.GetKeyName()
}

// GetNodeIP implements Node.
func (n *tableNode) GetNodeIP(ipv6 bool) net.IP {
	return n.node.GetNodeIP(ipv6)
}

func (n *tableNode) Node() types.Node {
	return n.node
}

func (n *tableNode) Local() *LocalNodeAttrs {
	return n.local
}

func (n *tableNode) IsLocal() bool {
	return n.local != nil
}

func (n *tableNode) TableHeader() []string {
	return []string{
		"Identity",
		"Source",
		"Node IP",
		"Health IP",
		"Ingress IP",
		"Alloc CIDRs",
	}
}

func joinStringers(ss ...fmt.Stringer) string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != nil {
			out = append(out, s.String())
		}
	}
	return strings.Join(out, ", ")
}

func (n *tableNode) TableRow() []string {
	addrs := make([]string, len(n.node.IPAddresses))
	if ip := n.GetNodeIP(false); ip != nil {
		addrs = append(addrs, ip.String())
	}
	if ip := n.GetNodeIP(true); ip != nil {
		addrs = append(addrs, ip.String())
	}
	return []string{
		n.GetKeyName(),
		string(n.Source()),
		joinStringers(n.GetNodeIP(false), n.GetNodeIP(true)),
		joinStringers(n.node.IPv4HealthIP, n.node.IPv6HealthIP),
		joinStringers(n.node.IPv4IngressIP, n.node.IPv6IngressIP),
		joinStringers(n.node.IPv4AllocCIDR, n.node.IPv6AllocCIDR),
	}
}

var _ Node = &tableNode{}

var (
	NodeIdentityIndex = statedb.Index[Node, types.Identity]{
		Name: "name",
		FromObject: func(node Node) index.KeySet {
			return index.NewKeySet(index.String(node.GetKeyName()))
		},
		FromKey: func(id types.Identity) index.Key {
			return index.String(types.GetKeyNodeName(id.Cluster, id.Name))
		},
		Unique: true,
	}

	NodeIPIndex = statedb.Index[Node, net.IP]{
		Name: "ip",
		FromObject: func(node Node) index.KeySet {
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

	NodeLocalIndex = statedb.Index[Node, bool]{
		Name: "local",
		FromObject: func(node Node) index.KeySet {
			return index.NewKeySet(index.Bool(node.IsLocal()))
		},
		FromKey: index.Bool,
		Unique:  true,
	}
)

func NewNodesTable(db *statedb.DB) (statedb.RWTable[Node], error) {
	tbl, err := statedb.NewTable(
		TableName,

		NodeIdentityIndex,
		NodeIPIndex,
		NodeLocalIndex,
	)
	if err == nil {
		err = db.RegisterTable(tbl)
	}
	return tbl, err
}

func GetLocalNode(txn statedb.ReadTxn, tbl statedb.Table[Node]) (Node, <-chan struct{}, bool) {
	n, _, watch, ok := tbl.GetWatch(txn, NodeLocalIndex.Query(true))
	return n, watch, ok
}
