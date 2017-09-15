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
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/maps/tunnel"

	log "github.com/sirupsen/logrus"
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

func deleteNodeCIDR(ip *net.IPNet) {
	if ip == nil {
		return
	}

	if err := tunnel.DeleteTunnelEndpoint(ip.IP); err != nil {
		log.Errorf("bpf: Unable to delete %s in tunnel endpoint map: %s", ip, err)
	}
}

func updateNodeCIDR(ip *net.IPNet, host net.IP) {
	if ip == nil {
		return
	}

	if err := tunnel.SetTunnelEndpoint(ip.IP, host); err != nil {
		log.Errorf("bpf: Unable to update %s in tunnel endpoint map: %s", ip, err)
	}
}

// UpdateNode updates the new node in the nodes' map with the given identity.
func UpdateNode(ni Identity, n *Node) {
	mutex.Lock()
	if oldNode, ok := nodes[ni]; ok {
		deleteNodeCIDR(oldNode.IPv4AllocCIDR)
		deleteNodeCIDR(oldNode.IPv6AllocCIDR)
	}

	// FIXME if PodCIDR is empty retrieve the CIDR from the KVStore

	log.Debugf("bpf: Setting tunnel endpoint %+v: %+v %+v",
		n.GetNodeIP(false), n.IPv4AllocCIDR, n.IPv6AllocCIDR)

	nodeIP := n.GetNodeIP(false)
	updateNodeCIDR(n.IPv4AllocCIDR, nodeIP)
	updateNodeCIDR(n.IPv6AllocCIDR, nodeIP)

	nodes[ni] = n

	mutex.Unlock()
}

// DeleteNode remove the node from the nodes' maps.
func DeleteNode(ni Identity) {
	var err1, err2 error
	mutex.Lock()
	if n, ok := nodes[ni]; ok {
		log.Debugf("bpf: Removing tunnel endpoint %+v: %+v %+v",
			n.GetNodeIP(false), n.IPv4AllocCIDR, n.IPv6AllocCIDR)

		if n.IPv4AllocCIDR != nil {
			err1 = tunnel.DeleteTunnelEndpoint(n.IPv4AllocCIDR.IP)
			if err1 == nil {
				n.IPv4AllocCIDR = nil
			}
		}

		if n.IPv6AllocCIDR != nil {
			err2 = tunnel.DeleteTunnelEndpoint(n.IPv6AllocCIDR.IP)
			if err2 == nil {
				n.IPv6AllocCIDR = nil
			}
		}
	}

	// Keep node around
	if err1 == nil && err2 == nil {
		delete(nodes, ni)
	}

	mutex.Unlock()
}
