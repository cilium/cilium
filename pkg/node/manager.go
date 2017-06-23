// Copyright 2016-2017 Authors of Cilium
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
	"sync"
)

var (
	mutex sync.RWMutex
	nodes = map[Identity]*Node{}
)

// GetNode returns the node with the given identity, if exists, from the nodes
// map.
func GetNode(ni Identity) *Node {
	mutex.RLock()
	n := nodes[ni]
	mutex.RUnlock()
	return n
}

// UpdateNode updates the new node in the nodes' map with the given identity.
func UpdateNode(ni Identity, n *Node) {
	mutex.Lock()
	//if oldNode, ok := nodes[ni]; ok {
	// oldNode
	// remove oldNode metadata (IPs-> endpoints CIDR) from bpf map
	//}

	// FIXME if PodCIDR is empty retrieve the CIDR from the KVStore

	// add new node changes to bpf map.
	// **note**: this will eventually add pod-cidr routes for the own node.

	nodes[ni] = n
	mutex.Unlock()

}

// DeleteNode remove the node from the nodes' maps.
func DeleteNode(ni Identity) {
	// remove node from bpf map

	mutex.Lock()
	delete(nodes, ni)
	mutex.Unlock()
}
