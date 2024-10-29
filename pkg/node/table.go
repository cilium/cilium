// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/node/types"
)

const (
	TableName = "nodes"
)

// LocalNodeAttrs are attributes attached only to the local Cilium node.
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

// TableNode is the concrete struct stored in the node table.
// This is exported and JSON serializable for cilium-dbg.
type TableNode struct {
	types.Node
	Local    *LocalNodeAttrs      `json:"local,omitempty"`
	Statuses reconciler.StatusSet `json:"statuses"`
}

func NewTableNode(n types.Node, l *LocalNodeAttrs) *TableNode {
	return &TableNode{Node: n, Local: l, Statuses: reconciler.NewStatusSet()}
}

func (n *TableNode) Clone() *TableNode {
	return &TableNode{
		Node:     *n.Node.DeepCopy(),
		Local:    n.Local.Clone(),
		Statuses: n.Statuses,
	}
}

func (n *TableNode) SetPending() {
	n.Statuses = n.Statuses.Pending()
}

func (n *TableNode) IsLocal() bool {
	return n.Local != nil
}

func (n *TableNode) TableHeader() []string {
	return []string{
		"Identity",
		"Source",
		"Node IP",
		"Health IP",
		"Ingress IP",
		"Alloc CIDRs",
		"Status",
	}
}

func joinStringers(ss ...fmt.Stringer) string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != nil && !reflect.ValueOf(s).IsNil() {
			out = append(out, s.String())
		}
	}
	return strings.Join(out, ", ")
}

func (n *TableNode) TableRow() []string {
	return []string{
		n.GetKeyName(),
		string(n.Source),
		joinStringers(n.GetNodeIP(false), n.GetNodeIP(true)),
		joinStringers(n.Node.IPv4HealthIP, n.Node.IPv6HealthIP),
		joinStringers(n.Node.IPv4IngressIP, n.Node.IPv6IngressIP),
		joinStringers(n.Node.IPv4AllocCIDR, n.Node.IPv6AllocCIDR),
		n.Statuses.String(),
	}
}

var (
	nodeIdentityIndex = statedb.Index[*TableNode, types.Identity]{
		Name: "name",
		FromObject: func(node *TableNode) index.KeySet {
			return index.NewKeySet(index.String(node.GetKeyName()))
		},
		FromKey: func(id types.Identity) index.Key {
			return index.String(types.GetKeyNodeName(id.Cluster, id.Name))
		},
		Unique: true,
	}

	ByIdentity = nodeIdentityIndex.Query

	nodeIPIndex = statedb.Index[*TableNode, net.IP]{
		Name: "ip",
		FromObject: func(node *TableNode) index.KeySet {
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

	ByIP = nodeIPIndex.Query

	nodeLocalIndex = statedb.Index[*TableNode, bool]{
		Name: "local",
		FromObject: func(node *TableNode) index.KeySet {
			return index.NewKeySet(index.Bool(node.IsLocal()))
		},
		FromKey: index.Bool,
		Unique:  true,
	}

	ByLocal = nodeLocalIndex.Query
)

func NewNodesTable(db *statedb.DB) (statedb.RWTable[*TableNode], error) {
	tbl, err := statedb.NewTable(
		TableName,

		nodeIdentityIndex,
		nodeIPIndex,
		nodeLocalIndex,
	)
	if err == nil {
		err = db.RegisterTable(tbl)
	}
	return tbl, err
}

func GetLocalNode(txn statedb.ReadTxn, tbl statedb.Table[*TableNode]) (*TableNode, <-chan struct{}, bool) {
	n, _, watch, ok := tbl.GetWatch(txn, ByLocal(true))
	return n, watch, ok
}
