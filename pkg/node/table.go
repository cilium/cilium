// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/node/types"
)

// LocalNode is the local Cilium node. This is derived from the k8s corev1.Node object.
//
// +k8s:deepcopy-gen=true
// +deepequal-gen=true
type LocalNode struct {
	types.Node

	// Local is non-nil if this is the local node. This carries additional
	// information about the local node that is not shared outside.
	Local *LocalNodeInfo
}

// TableHeader implements statedb.TableWritable.
func (n *LocalNode) TableHeader() []string {
	return []string{
		"Name",
		"Source",
		"Addresses",
	}
}

// TableRow implements statedb.TableWritable.
func (n *LocalNode) TableRow() []string {
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

var _ statedb.TableWritable = &LocalNode{}

// LocalNodeInfo is the additional information about the local node that
// is only used internally.
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=true
// +deepequal-gen:private-method=true
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
	// +deepequal-gen=false
	ServiceLoopbackIPv4 netip.Addr
	// ServiceLoopbackIPv6 is the source address used for SNAT when a Pod talks to
	// itself through a Service.
	// +deepequal-gen=false
	ServiceLoopbackIPv6 netip.Addr
	// IsBeingDeleted indicates that the local node is being deleted.
	IsBeingDeleted bool
	// UnderlayProtocol is the IP family of our underlay.
	UnderlayProtocol tunnel.UnderlayProtocol
}

// DeepCopyInto copies the receiver into out. in must be non-nil.
func (in *LocalNodeInfo) DeepCopyInto(out *LocalNodeInfo) {
	*out = *in
	// Deep copy pointer fields
	if in.IPv4NativeRoutingCIDR != nil {
		out.IPv4NativeRoutingCIDR = in.IPv4NativeRoutingCIDR.DeepCopy()
	}
	if in.IPv6NativeRoutingCIDR != nil {
		out.IPv6NativeRoutingCIDR = in.IPv6NativeRoutingCIDR.DeepCopy()
	}
	// netip.Addr fields are value types, already copied by *out = *in
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

// DeepEqual compares two LocalNodeInfo structs for equality.
func (in *LocalNodeInfo) DeepEqual(other *LocalNodeInfo) bool {
	if other == nil {
		return false
	}
	// Manually compare netip.Addr fields
	if in.ServiceLoopbackIPv4 != other.ServiceLoopbackIPv4 {
		return false
	}
	if in.ServiceLoopbackIPv6 != other.ServiceLoopbackIPv6 {
		return false
	}
	// Call generated private method for other fields
	return in.deepEqual(other)
}

const (
	LocalNodeTableName = "local-node"
)

var (
	LocalNodeNameIndex = statedb.Index[*LocalNode, string]{
		Name: "name",
		FromObject: func(obj *LocalNode) index.KeySet {
			return index.NewKeySet(index.String(obj.Fullname()))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
	NodeByName = LocalNodeNameIndex.Query

	LocalNodeLocalIndex = statedb.Index[*LocalNode, bool]{
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

	NodeByLocal    = LocalNodeLocalIndex.Query
	LocalNodeQuery = NodeByLocal(true)
)

func NewLocalNodeTable(db *statedb.DB) (statedb.RWTable[*LocalNode], error) {
	return statedb.NewTable(
		db,
		LocalNodeTableName,
		LocalNodeNameIndex,
		LocalNodeLocalIndex,
	)
}
