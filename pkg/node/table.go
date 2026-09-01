// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	k8stypes "k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
)

// LocalNode is an alias for the [Node] type to mark that we expect this
// to be the local node.
type LocalNode = Node

// Node is a Cilium node. It is the local node if [Node.Local] is non-nil.
//
// +deepequal-gen=true
type Node struct {
	types.Node

	// addressClusterID identifies the cluster address space used by
	// cluster-scoped node addresses. It is derived when the node is written and
	// is not part of the externally serialized node data.
	// +deepequal-gen=false
	addressClusterID uint32

	// Local is non-nil if this is the local node. This carries additional
	// information about the local node that is not shared outside.
	Local *LocalNodeInfo

	// Statuses for reconcilers acting on this object.
	// DeepEqual is reserved for comparing the desired node data.
	// +deepequal-gen=false
	Statuses reconciler.StatusSet
}

// DeepCopy returns a deep copy of the node.
func (n *Node) DeepCopy() *Node {
	n2 := *n
	n2.Node = *n2.Node.DeepCopy()
	n2.Local = n2.Local.DeepCopy()
	return &n2
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
// Every field is a comparable value type, which lets DeepCopyInto and
// DeepEqual below be a plain assignment and a plain comparison.
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
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
	IPv4NativeRoutingCIDR netip.Prefix
	// v6 CIDR in which pod IPs are routable
	IPv6NativeRoutingCIDR netip.Prefix
	// ServiceLoopbackIPv4 is the source address used for SNAT when a Pod talks to
	// itself through a Service.
	ServiceLoopbackIPv4 netip.Addr
	// ServiceLoopbackIPv6 is the source address used for SNAT when a Pod talks to
	// itself through a Service.
	ServiceLoopbackIPv6 netip.Addr
	// IsBeingDeleted indicates that the local node is being deleted.
	IsBeingDeleted bool
	// UnderlayProtocol is the IP family of our underlay.
	UnderlayProtocol tunnel.UnderlayProtocol
}

// DeepCopyInto copies the receiver into out. in must be non-nil.
func (in *LocalNodeInfo) DeepCopyInto(out *LocalNodeInfo) {
	*out = *in
}

// DeepCopy creates a deep copy of the LocalNodeInfo.
func (in *LocalNodeInfo) DeepCopy() *LocalNodeInfo {
	if in == nil {
		return nil
	}
	out := new(LocalNodeInfo)
	in.DeepCopyInto(out)
	return out
}

// DeepEqual compares two LocalNodeInfo structs for equality. in must be non-nil.
func (in *LocalNodeInfo) DeepEqual(other *LocalNodeInfo) bool {
	if other == nil {
		return false
	}
	return *in == *other
}

const (
	NodeTableName = "nodes"
)

var (
	NodeNameIndex = statedb.Index[*Node, string]{
		Name: "name",
		FromObject: func(obj *LocalNode) index.KeySet {
			return index.NewKeySet(index.String(obj.Fullname()))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
	NodeByName = NodeNameIndex.Query

	// NodeAddressIndex indexes every address of the node. The index is non-unique
	// because configured Cilium internal router addresses may legitimately be
	// shared by every node. Writer resolves all other conflicts according to
	// source priority.
	NodeAddressIndex = statedb.Index[*Node, cmtypes.AddrCluster]{
		Name: "address",
		FromObject: func(obj *Node) index.KeySet {
			keys := make([]index.Key, 0, len(obj.IPAddresses)+4)
			appendAddr := func(addr netip.Addr, clusterID uint32) {
				if addr.IsValid() {
					addrCluster := cmtypes.AddrClusterFrom(addr.Unmap(), clusterID)
					keys = append(keys, nodeAddressKey(addrCluster))
				}
			}
			for _, address := range obj.IPAddresses {
				if addr, ok := netip.AddrFromSlice(address.IP); ok {
					clusterID := uint32(0)
					if address.Type == addressing.NodeCiliumInternalIP {
						clusterID = obj.addressClusterID
					}
					appendAddr(addr, clusterID)
				}
			}
			appendAddr(obj.IPv4HealthIP.Addr, obj.addressClusterID)
			appendAddr(obj.IPv6HealthIP.Addr, obj.addressClusterID)
			appendAddr(obj.IPv4IngressIP.Addr, obj.addressClusterID)
			appendAddr(obj.IPv6IngressIP.Addr, obj.addressClusterID)
			return index.NewKeySet(keys...)
		},
		FromKey:    nodeAddressKey,
		FromString: nodeAddressKeyString,
		Unique:     false,
	}
	NodeByAddress = NodeAddressIndex.Query

	NodeLocalIndex = statedb.Index[*Node, bool]{
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

func nodeAddressKey(addr cmtypes.AddrCluster) index.Key {
	key := addr.As20()
	return key[:]
}

func nodeAddressKeyString(s string) (index.Key, error) {
	addr, err := cmtypes.ParseAddrCluster(s)
	if err != nil {
		return nil, err
	}
	return nodeAddressKey(addr), nil
}

func NewNodeTable(db *statedb.DB) (statedb.RWTable[*Node], error) {
	return statedb.NewTable(
		db,
		NodeTableName,
		NodeNameIndex,
		NodeLocalIndex,
		NodeAddressIndex,
	)
}
