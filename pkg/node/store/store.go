// Copyright 2018-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"context"
	"fmt"
	"path"
	"time"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
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

// NodeObserver implements the store.Observer interface and delegates update
// and deletion events to the node object itself.
type NodeObserver struct {
	manager NodeManager
}

// NewNodeObserver returns a new NodeObserver associated with the specified
// node manager
func NewNodeObserver(manager NodeManager) *NodeObserver {
	return &NodeObserver{manager: manager}
}

func (o *NodeObserver) OnUpdate(k store.Key) {
	if n, ok := k.(*nodeTypes.Node); ok {
		nodeCopy := n.DeepCopy()
		nodeCopy.Source = source.KVStore
		o.manager.NodeUpdated(*nodeCopy)
	}
}

func (o *NodeObserver) OnDelete(k store.NamedKey) {
	if n, ok := k.(*nodeTypes.Node); ok {
		nodeCopy := n.DeepCopy()
		nodeCopy.Source = source.KVStore
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

	// Exists is called to verify if a node exists
	Exists(id nodeTypes.Identity) bool
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
		Prefix:     NodeRegisterStorePrefix,
		KeyCreator: RegisterKeyCreator,
		Observer:   registerObserver,
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
func (nr *NodeRegistrar) RegisterNode(n *nodeTypes.Node, manager NodeManager) error {
	if option.Config.KVStore == "" {
		return nil
	}

	// Join the shared store holding node information of entire cluster
	nodeStore, err := store.JoinSharedStore(store.Configuration{
		Prefix:     NodeStorePrefix,
		KeyCreator: KeyCreator,
		Observer:   NewNodeObserver(manager),
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
