// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"fmt"
	"path"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
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
	NodeStorePrefix = path.Join(kvstore.BaseKeyPrefix, "state", "nodes", "v1")

	// KeyCreator creates a node for a shared store
	KeyCreator = func() store.Key {
		n := nodeTypes.Node{}
		return &n
	}

	// NodeRegisterStorePrefix is the kvstore prefix of the shared
	// store for node registration
	//
	// WARNING - STABLE API: Changing the structure or values of this will
	// break backwards compatibility
	NodeRegisterStorePrefix = path.Join(kvstore.BaseKeyPrefix, "state", "noderegister", "v1")

	// RegisterKeyCreator creates a node for a shared store
	RegisterKeyCreator = func() store.Key {
		n := nodeTypes.RegisterNode{}
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
	manager NodeManager
	source  source.Source
}

// NewNodeObserver returns a new NodeObserver associated with the specified
// node manager
func NewNodeObserver(manager NodeManager, source source.Source) *NodeObserver {
	return &NodeObserver{manager: manager, source: source}
}

func (o *NodeObserver) OnUpdate(k store.Key) {
	if n, ok := k.(*ValidatingNode); ok && !n.IsLocal() {
		nodeCopy := n.DeepCopy()
		nodeCopy.Source = o.source
		o.manager.NodeUpdated(*nodeCopy)
	}
}

func (o *NodeObserver) OnDelete(k store.NamedKey) {
	if n, ok := k.(*ValidatingNode); ok && !n.IsLocal() {
		nodeCopy := n.DeepCopy()
		nodeCopy.Source = o.source
		o.manager.NodeDeleted(*nodeCopy)
	}
}

// NodeManager is the interface that the manager of nodes has to implement
type NodeManager interface {
	// NodeUpdated is called when the store detects a change in node
	// information
	NodeUpdated(n nodeTypes.Node)

	// NodeDeleted is called when the store detects a deletion of a node
	NodeDeleted(n nodeTypes.Node)
}

type NodeExtendedManager interface {
	NodeManager

	// NodeSync is called when the store completes the initial nodes listing
	NodeSync()
}

// NodeRegistrar is a wrapper around store.SharedStore.
type NodeRegistrar struct {
	*store.SharedStore

	registerStore *store.SharedStore
}

// RegisterObserver implements the store.Observer interface and sends
// named node's identity updates on a channel.
type RegisterObserver struct {
	name    string
	updates chan *nodeTypes.RegisterNode
}

// NewRegisterObserver returns a new RegisterObserver
func NewRegisterObserver(name string, updateChan chan *nodeTypes.RegisterNode) *RegisterObserver {
	return &RegisterObserver{
		name:    name,
		updates: updateChan,
	}
}

func (o *RegisterObserver) OnUpdate(k store.Key) {
	if n, ok := k.(*nodeTypes.RegisterNode); ok {
		log.Debugf("noderegister update on key %s while waiting for %s: %v", n.GetKeyName(), o.name, n)
		if n.NodeIdentity != 0 && n.GetKeyName() == o.name {
			select {
			case o.updates <- n:
			default:
				// Register Node updateChan would block, not sending
			}
		}
	}
}

func (o *RegisterObserver) OnDelete(k store.NamedKey) {
	log.Debugf("noderegister key %s deleted while registering %s", k.GetKeyName(), o.name)
}

// JoinCluster registers the local node in the cluster.
// Blocks until timeout occurs or an updated Node is received from the kv-store and returns it.
// Otherwise this does not block and returns nil.
func (nr *NodeRegistrar) JoinCluster(name string) (*nodeTypes.Node, error) {
	n := &nodeTypes.RegisterNode{
		Node: nodeTypes.Node{
			Name:   name,
			Source: source.Local,
		},
	}

	registerObserver := NewRegisterObserver(n.GetKeyName(), make(chan *nodeTypes.RegisterNode, 10))
	// Join the shared store for node registrations
	registerStore, err := store.JoinSharedStore(store.Configuration{
		Prefix:               NodeRegisterStorePrefix,
		KeyCreator:           RegisterKeyCreator,
		SharedKeyDeleteDelay: defaults.NodeDeleteDelay,
		Observer:             registerObserver,
	})
	if err != nil {
		return nil, err
	}

	// Drain the channel of old updates first
	for len(registerObserver.updates) > 0 {
		dump := <-registerObserver.updates
		log.Debugf("bypassing stale noderegister key: %s", dump.GetKeyName())
	}

	log.Debugf("updating noderegister key %s with: %v", n.GetKeyName(), n)
	err = registerStore.UpdateLocalKeySync(context.TODO(), n)
	if err != nil {
		registerStore.Release()
		return nil, err
	}

	// Wait until an updated key is received from the kvstore
	select {
	case n = <-registerObserver.updates:
	case <-time.After(defaults.NodeInitTimeout / 10):
		registerStore.Release()
		return nil, fmt.Errorf("timed out waiting for node identity")
	}

	nr.registerStore = registerStore
	return &n.Node, nil
}

// RegisterNode registers the local node in the cluster.
func (nr *NodeRegistrar) RegisterNode(n *nodeTypes.Node, manager NodeExtendedManager) error {
	if option.Config.KVStore == "" {
		return nil
	}

	// Join the shared store holding node information of entire cluster
	nodeStore, err := store.JoinSharedStore(store.Configuration{
		Prefix:               NodeStorePrefix,
		KeyCreator:           ValidatingKeyCreator(),
		SharedKeyDeleteDelay: defaults.NodeDeleteDelay,
		Observer:             NewNodeObserver(manager, source.KVStore),
	})
	if err != nil {
		return err
	}

	// Use nodeTypes.RegisterNode for updating local node info if not nil, but keep nodeStore for cluster node updates
	if nr.registerStore != nil {
		err = nr.registerStore.UpdateLocalKeySync(context.TODO(), &nodeTypes.RegisterNode{Node: *n})
	} else {
		err = nodeStore.UpdateLocalKeySync(context.TODO(), n)
	}
	if err != nil {
		nodeStore.Release()
		return err
	}

	nr.SharedStore = nodeStore

	manager.NodeSync()

	return nil
}

// UpdateLocalKeySync synchronizes the local key for the node using the
// SharedStore.
func (nr *NodeRegistrar) UpdateLocalKeySync(n *nodeTypes.Node) error {
	if nr.registerStore != nil {
		return nr.registerStore.UpdateLocalKeySync(context.TODO(), &nodeTypes.RegisterNode{Node: *n})
	}
	return nr.SharedStore.UpdateLocalKeySync(context.TODO(), n)
}
