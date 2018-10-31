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

	nodeStore *store.SharedStore
)

type NodeRegistrar struct{}

// RegisterNode registers the local node in the cluster
func (nr *NodeRegistrar) RegisterNode(n *node.Node) error {

	// Join the shared store holding node information of entire cluster
	store, err := store.JoinSharedStore(store.Configuration{
		Prefix:                  NodeStorePrefix,
		KeyCreator:              KeyCreator,
		SynchronizationInterval: time.Minute,
	})

	if err != nil {
		return err
	}

	if err = store.UpdateLocalKeySync(n); err != nil {
		store.Close()
		return err
	}

	nodeStore = store

	return nil
}

func (nr *NodeRegistrar) UpdateLocalKeySync(n *node.Node) error {
	return nodeStore.UpdateLocalKeySync(n)
}
