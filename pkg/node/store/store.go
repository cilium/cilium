// Copyright 2018 Authors of Cilium
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
	"path"
	"time"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/node"
)

var (
	// NodeStorePrefix is the kvstore prefix of the shared store
	//
	// WARNING - STABLE API: Changing the structure or values of this will
	// break backwards compatibility
	NodeStorePrefix = path.Join(kvstore.BaseKeyPrefix, "state", "nodes", "v1")

	// KeyCreator creates a node for a shared store
	KeyCreator = func() store.Key {
		n := node.Node{}
		return &n
	}
)

// NodeObserver implements the store.Observer interface and delegates update
// and deletion events to the node object itself.
type NodeObserver struct {
	manager NodeManager
}

func (o *NodeObserver) OnUpdate(k store.Key) {
	if n, ok := k.(*node.Node); ok {
		nodeCopy := n.DeepCopy()
		nodeCopy.Source = node.FromKVStore
		o.manager.NodeUpdated(*nodeCopy)
	}
}

func (o *NodeObserver) OnDelete(k store.Key) {
	if n, ok := k.(*node.Node); ok {
		nodeCopy := n.DeepCopy()
		nodeCopy.Source = node.FromKVStore
		o.manager.NodeDeleted(*nodeCopy)
	}
}

// NodeRegistrar is a wrapper around store.SharedStore.
type NodeRegistrar struct {
	*store.SharedStore
}

// NodeManager is the interface that the manager of nodes has to implement
type NodeManager interface {
	// NodeUpdated is called when the store detects a change in node
	// information
	NodeUpdated(n node.Node)

	// NodeDeleted is called when the store detects a deletion of a node
	NodeDeleted(n node.Node)
}

// RegisterNode registers the local node in the cluster
func (nr *NodeRegistrar) RegisterNode(n *node.Node, manager NodeManager) error {

	// Join the shared store holding node information of entire cluster
	store, err := store.JoinSharedStore(store.Configuration{
		Prefix:                  NodeStorePrefix,
		KeyCreator:              KeyCreator,
		SynchronizationInterval: time.Minute,
		Observer:                &NodeObserver{manager: manager},
	})

	if err != nil {
		return err
	}

	if err = store.UpdateLocalKeySync(n); err != nil {
		store.Close()
		return err
	}

	nr.SharedStore = store

	return nil
}

// UpdateLocalKeySync synchronizes the local key for the node using the
// SharedStore.
func (nr *NodeRegistrar) UpdateLocalKeySync(n *node.Node) error {
	return nr.SharedStore.UpdateLocalKeySync(n)
}
