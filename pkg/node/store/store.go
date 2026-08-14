// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// NodeStorePrefix is the kvstore prefix of the shared store
	//
	// WARNING - STABLE API: Changing the structure or values of this will
	// break backwards compatibility
	NodeStorePrefix = kvstore.JoinKey(kvstore.BaseKeyPrefix, "state", "nodes", "v1")

	// KeyCreator creates a node for a shared store
	KeyCreator = func() store.Key {
		n := nodeTypes.Node{}
		return &n
	}
)

// ValidatingNode wraps a Node to perform additional validation at unmarshal time.
type ValidatingNode struct {
	nodeTypes.Node

	validators []nodeValidator
}

type nodeValidator func(key string, n *nodeTypes.Node) error

func (vn *ValidatingNode) Unmarshal(key string, data []byte) error {
	if err := vn.Node.Unmarshal(key, data); err != nil {
		return err
	}

	for _, validator := range vn.validators {
		if err := validator(key, &vn.Node); err != nil {
			return err
		}
	}

	return nil
}

// ClusterNameValidator returns a validator enforcing that the cluster field
// of the unmarshaled node matches the provided one.
func ClusterNameValidator(clusterName string) nodeValidator {
	return func(_ string, n *nodeTypes.Node) error {
		if n.Cluster != clusterName {
			return fmt.Errorf("unexpected cluster name: got %s, expected %s", n.Cluster, clusterName)
		}
		return nil
	}
}

// NameValidator returns a validator enforcing that the name of the the unmarshaled
// node matches the kvstore key.
func NameValidator() nodeValidator {
	return func(key string, n *nodeTypes.Node) error {
		if n.Name != key {
			return fmt.Errorf("name does not match key: got %s, expected %s", n.Name, key)
		}
		return nil
	}
}

// ClusterIDValidator returns a validator enforcing that the cluster ID of the
// unmarshaled node matches the provided one. The access to the provided
// clusterID value is not synchronized, and it shall not be mutated concurrently.
func ClusterIDValidator(clusterID *uint32) nodeValidator {
	return func(_ string, n *nodeTypes.Node) error {
		if n.ClusterID != *clusterID {
			return fmt.Errorf("unexpected cluster ID: got %d, expected %d", n.ClusterID, *clusterID)
		}
		return nil
	}
}

// ValidatingKeyCreator returns a store.KeyCreator for Nodes, configuring the
// specified extra validators.
func ValidatingKeyCreator(validators ...nodeValidator) store.KeyCreator {
	return func() store.Key {
		return &ValidatingNode{validators: validators}
	}
}

// NodeObserver implements the store.Observer interface and delegates update
// and deletion events to the node object itself.
type NodeObserver struct {
	writer Writer
	source source.Source
	db     *statedb.DB
	nodes  statedb.Table[*node.Node]
}

// NewNodeObserver returns a new NodeObserver associated with the specified
// node writer.
func NewNodeObserver(db *statedb.DB, nodes statedb.Table[*node.Node], writer Writer, source source.Source) *NodeObserver {
	return &NodeObserver{writer: writer, source: source, db: db, nodes: nodes}
}

func (o *NodeObserver) OnUpdate(k store.Key) {
	if n, ok := k.(*ValidatingNode); ok && !n.IsLocal() {
		nodeCopy := n.DeepCopy()
		nodeCopy.Source = o.source
		txn := o.db.WriteTxn(o.nodes)
		defer txn.Abort()
		o.writer.Upsert(txn, nodeCopy)
		txn.Commit()
	}
}

func (o *NodeObserver) OnDelete(k store.NamedKey) {
	if n, ok := k.(*ValidatingNode); ok && !n.IsLocal() {
		nodeCopy := n.DeepCopy()
		nodeCopy.Source = o.source
		txn := o.db.WriteTxn(o.nodes)
		defer txn.Abort()
		o.writer.Delete(txn, nodeCopy.Source, nodeCopy.Identity())
		txn.Commit()
	}
}

// Writer is the node table mutation interface used by store observers.
type Writer interface {
	Upsert(statedb.WriteTxn, *nodeTypes.Node) bool
	Delete(statedb.WriteTxn, source.Source, nodeTypes.Identity) bool
}

// NodeRegistrar is a wrapper around store.SharedStore.
type NodeRegistrar struct {
	*store.SharedStore
}

// RegisterNode registers the local node in the cluster.
func (nr *NodeRegistrar) RegisterNode(ctx context.Context, logger *slog.Logger, client kvstore.Client, n *nodeTypes.Node, db *statedb.DB, nodes statedb.Table[*node.Node], writer Writer, initialized func(statedb.WriteTxn)) error {
	if !client.IsEnabled() {
		return nil
	}

	// Join the shared store holding node information of entire cluster
	nodeStore, err := store.JoinSharedStore(logger, store.Configuration{
		Context:                 ctx,
		Backend:                 client,
		Prefix:                  NodeStorePrefix,
		KeyCreator:              ValidatingKeyCreator(),
		SynchronizationInterval: 30 * time.Minute,
		SharedKeyDeleteDelay:    defaults.NodeDeleteDelay,
		Observer:                NewNodeObserver(db, nodes, writer, source.KVStore),
	})
	if err != nil {
		return err
	}

	err = nodeStore.UpdateLocalKeySync(ctx, copyForRemoteNodes(n))
	if err != nil {
		nodeStore.Release()
		return err
	}

	nr.SharedStore = nodeStore

	txn := db.WriteTxn(nodes)
	initialized(txn)
	txn.Commit()

	return nil
}

// UpdateLocalKeySync synchronizes the local key for the node using the
// SharedStore.
func (nr *NodeRegistrar) UpdateLocalKeySync(ctx context.Context, n *nodeTypes.Node) error {
	return nr.SharedStore.UpdateLocalKeySync(ctx, copyForRemoteNodes(n))
}

func copyForRemoteNodes(n *nodeTypes.Node) *nodeTypes.Node {
	node := n.DeepCopy()
	switch option.Config.IPAM {
	case ipamOption.IPAMKubernetes, ipamOption.IPAMClusterPool, ipamOption.IPAMMultiPool:
		// Keep the PodCIDRs as they are valid.
	default:
		// Strip the PodCIDRs on non-podCIDR based IPAM modes (e.g. ENI, Azure, AlibabaCloud). In
		// those cases, the IPv4/IPv6AllocRange is auto-generated and otherwise unused, so it does
		// not make sense to copy it to the kvstore.
		// See NodeDiscovery.mutateNodeResource() for the equivalent CRD mode logic.
		node.IPv4AllocCIDR = nodeTypes.Prefix{}
		node.IPv4SecondaryAllocCIDRs = nil
		node.IPv6AllocCIDR = nodeTypes.Prefix{}
		node.IPv6SecondaryAllocCIDRs = nil
	}
	return node
}
