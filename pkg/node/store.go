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

package node

import (
	"encoding/json"
	"path"
	"time"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

var (
	// nodesStorePrefix is the kvstore prefix of the shared store
	//
	// WARNING - STABLE API: Changing the structure or values of this will
	// break backwards compatibility
	nodeStorePrefix = path.Join(kvstore.BaseKeyPrefix, "state", "nodes", "v1")

	nodeStore *store.SharedStore
)

// GetKeyName returns the kvstore key to be used for the node
func (n *Node) GetKeyName() string {
	// WARNING - STABLE API: Changing the structure of the key may break
	// backwards compatibility
	return path.Join(n.cluster.name, n.Name)
}

// Marshal returns the node object as JSON byte slice
func (n *Node) Marshal() ([]byte, error) {
	return json.Marshal(n)
}

// Unmarshal parses the JSON byte slice and updates the node receiver
func (n *Node) Unmarshal(data []byte) error {
	return json.Unmarshal(data, n)
}

// registerNode registers the local node in the cluster
func registerNode() error {
	localNode.getLogger().Info("Adding local node to cluster")

	// Join the shared store holding node information of entire cluster
	store, err := store.JoinSharedStore(store.Configuration{
		Prefix: nodeStorePrefix,
		KeyCreator: func() store.Key {
			n := Node{}
			return &n
		},
		SynchronizationInterval: time.Minute,
	})

	if err != nil {
		return err
	}

	if err = store.UpdateLocalKeySync(&localNode); err != nil {
		store.Close()
		return err
	}

	nodeStore = store

	return nil
}
