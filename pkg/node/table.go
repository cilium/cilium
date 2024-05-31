// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"fmt"
	"maps"
	"net"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
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
	GetNode() types.Node

	// GetLocal returns the extra information carried for the local node. Nil if this
	// node is not the local node.
	GetLocal() *LocalNodeAttrs

	IsLocal() bool

	Builder() *NodeBuilder

	TableHeader() []string
	TableRow() []string

	// Clone returns a shallow clone of the node. Meant to be used as the [CloneObject]
	// method for a reconciler.
	Clone() Node

	// GetReconciliationStatus gets the reconciliation status of the given
	// reconciler. If the status is not set for the reconciler then it returns
	// pending.
	// Meant to be used as the [GetObjectStatus] method for a reconciler.
	GetReconciliationStatus(reconciler string) reconciler.Status

	// SetReconciliationStatus sets the reconciliation status for the given
	// reconciler. Must call Clone() before using this method.
	// Meant to be used as the [SetObjectStatus] method for a reconciler.
	SetReconciliationStatus(reconciler string, status reconciler.Status) Node
}

type NodeBuilder struct {
	orig *TableNode
	new  *TableNode
}

func (b *NodeBuilder) Build() (Node, error) {
	if !source.AllowOverwrite(b.orig.Source(), b.new.Source()) {
		return nil, fmt.Errorf("source %q cannot overwrite %q", b.new.Source(), b.orig.Source())
	}
	return b.new, nil
}

func (b *NodeBuilder) ModifyNode(mod func(n *types.Node)) *NodeBuilder {
	mod(&b.new.Node)
	return b
}

func (b *NodeBuilder) ModifyLocal(mod func(l *LocalNodeAttrs)) *NodeBuilder {
	if b.new.Local == nil {
		b.new.Local = &LocalNodeAttrs{}
	}
	mod(b.new.Local)
	return b
}

// TableNode is the concrete struct stored in the node table.
// This is exported and JSON serializable for cilium-dbg.
type TableNode struct {
	Node     types.Node                   `json:"node"`
	Local    *LocalNodeAttrs              `json:"local,omitempty"`
	Statuses map[string]reconciler.Status `json:"statuses,omitempty"`
}

var emptyStatusMap = map[string]reconciler.Status{}

func NewTableNode(n types.Node, l *LocalNodeAttrs) Node {
	return &TableNode{Node: n, Local: l, Statuses: emptyStatusMap}
}

func (n *TableNode) Clone() Node {
	return &TableNode{
		Node:     n.Node,
		Local:    n.Local,
		Statuses: n.Statuses,
	}
}

func (n *TableNode) GetReconciliationStatus(rc string) reconciler.Status {
	status, ok := n.Statuses[rc]
	if ok {
		return status
	}
	// If no existing status, then we assume it's pending. This allows
	// just setting the map to empty to indicate pending.
	return reconciler.StatusPending()
}

func (n *TableNode) SetReconciliationStatus(rc string, status reconciler.Status) Node {
	n.Statuses = maps.Clone(n.Statuses)
	n.Statuses[rc] = status
	return n
}

func (n *TableNode) Builder() *NodeBuilder {
	return &NodeBuilder{
		orig: n,
		new: &TableNode{
			Node:     *n.Node.DeepCopy(),
			Local:    n.Local.Clone(),
			Statuses: emptyStatusMap,
		},
	}
}

func (n *TableNode) Name() string {
	return n.Node.Name
}

func (n *TableNode) Source() source.Source {
	return n.Node.Source
}

func (n *TableNode) Identity() types.Identity {
	return n.Node.Identity()
}

// Cluster implements Node.
func (n *TableNode) Cluster() string {
	return n.Node.Cluster
}

// GetKeyName implements Node.
func (n *TableNode) GetKeyName() string {
	return n.Node.GetKeyName()
}

// GetNodeIP implements Node.
func (n *TableNode) GetNodeIP(ipv6 bool) net.IP {
	return n.Node.GetNodeIP(ipv6)
}

func (n *TableNode) GetNode() types.Node {
	return n.Node
}

func (n *TableNode) GetLocal() *LocalNodeAttrs {
	return n.Local
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
		"Reconciliation",
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

func (n *TableNode) TableRow() []string {
	addrs := make([]string, 0, len(n.Node.IPAddresses))
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
		joinStringers(n.Node.IPv4HealthIP, n.Node.IPv6HealthIP),
		joinStringers(n.Node.IPv4IngressIP, n.Node.IPv6IngressIP),
		joinStringers(n.Node.IPv4AllocCIDR, n.Node.IPv6AllocCIDR),
		collapseStatuses(n.Statuses),
	}
}

func collapseStatuses(s map[string]reconciler.Status) string {
	// TODO clean this up

	if len(s) == 0 {
		// All pending
		return "Pending"
	}

	var updatedAt time.Time

	done := []string{}
	pending := []string{}
	errored := []string{}
	for name, status := range s {
		if status.UpdatedAt.After(updatedAt) {
			updatedAt = status.UpdatedAt
		}
		switch status.Kind {
		case reconciler.StatusKindDone:
			done = append(done, name)
		case reconciler.StatusKindError:
			errored = append(errored, name+" ("+status.Error+")")
		default:
			pending = append(pending, name)
		}
	}
	out := ""
	if len(errored) > 0 {
		out += "Errored: " + strings.Join(errored, " ")
	}
	if len(pending) > 0 {
		if len(out) > 0 {
			out += ", "
		}
		out += "Pending: " + strings.Join(pending, " ")
	}
	if len(done) > 0 {
		if len(out) > 0 {
			out += ", "
		}
		out += "Done: " + strings.Join(done, " ")
	}
	return out + " -- " + prettySince(updatedAt) + " ago"
}

// copy-pasta from statedb reconciler
func prettySince(t time.Time) string {
	ago := float64(time.Now().Sub(t)) / float64(time.Millisecond)
	// millis
	if ago < 1000.0 {
		return fmt.Sprintf("%.1fms", ago)
	}
	// secs
	ago /= 1000.0
	if ago < 60.0 {
		return fmt.Sprintf("%.1fs", ago)
	}
	// mins
	ago /= 60.0
	if ago < 60.0 {
		return fmt.Sprintf("%.1fm", ago)
	}
	// hours
	ago /= 60.0
	return fmt.Sprintf("%.1fh", ago)
}

var _ Node = &TableNode{}

var (
	nodeIdentityIndex = statedb.Index[Node, types.Identity]{
		Name: "name",
		FromObject: func(node Node) index.KeySet {
			return index.NewKeySet(index.String(node.GetKeyName()))
		},
		FromKey: func(id types.Identity) index.Key {
			return index.String(types.GetKeyNodeName(id.Cluster, id.Name))
		},
		Unique: true,
	}

	ByIdentity = nodeIdentityIndex.Query

	nodeIPIndex = statedb.Index[Node, net.IP]{
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

	ByIP = nodeIPIndex.Query

	nodeLocalIndex = statedb.Index[Node, bool]{
		Name: "local",
		FromObject: func(node Node) index.KeySet {
			return index.NewKeySet(index.Bool(node.IsLocal()))
		},
		FromKey: index.Bool,
		Unique:  true,
	}

	ByLocal = nodeLocalIndex.Query
)

func NewNodesTable(db *statedb.DB) (statedb.RWTable[Node], error) {
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

func GetLocalNode(txn statedb.ReadTxn, tbl statedb.Table[Node]) (Node, <-chan struct{}, bool) {
	n, _, watch, ok := tbl.GetWatch(txn, ByLocal(true))
	return n, watch, ok
}
