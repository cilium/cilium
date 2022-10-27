// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

const (
	minNodeID = 1
	maxNodeID = idpool.ID(^uint16(0))
)

// AllocateNodeID allocates a new ID for the given node (by IP) if one wasn't
// already assigned.
func (n *linuxNodeHandler) AllocateNodeID(nodeIP net.IP) uint16 {
	if len(nodeIP) == 0 || nodeIP.IsUnspecified() {
		// This should never happen. If it ever does, we may have an unexpected
		// call to AllocateNodeID.
		log.Warning("Attempt to allocate a node ID for an empty node IP address")
		return 0
	}

	// Don't allocate a node ID for the local node.
	localNode := node.GetIPv4()
	if localNode.Equal(nodeIP) {
		return 0
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	if nodeID, exists := n.nodeIDsByIPs[nodeIP.String()]; exists {
		return nodeID
	}

	nodeID := uint16(n.nodeIDs.AllocateID())
	if nodeID == uint16(idpool.NoID) {
		log.Error("No more IDs available for nodes")
	} else {
		log.WithFields(logrus.Fields{
			logfields.NodeID: nodeID,
			logfields.IPAddr: nodeIP,
		}).Debug("Allocated new node ID for node IP address")
	}
	n.nodeIDsByIPs[nodeIP.String()] = nodeID
	return nodeID
}

// allocateIDForNode allocates a new ID for the given node if one hasn't already
// been assigned. If any of the node IPs have an ID associated, then all other
// node IPs receive the same. This might happen if we allocated a node ID from
// the ipcache, where we don't have all node IPs but only one.
func (n *linuxNodeHandler) allocateIDForNode(node *nodeTypes.Node) uint16 {
	nodeID := uint16(0)

	// Did we already allocate a node ID for any IP of that node?
	for _, addr := range node.IPAddresses {
		if id, exists := n.nodeIDsByIPs[addr.IP.String()]; exists {
			nodeID = id
		}
	}

	if nodeID == 0 {
		nodeID = uint16(n.nodeIDs.AllocateID())
		if nodeID == uint16(idpool.NoID) {
			log.WithField(logfields.NodeName, node.Name).Error("No more IDs available for nodes")
		} else {
			log.WithFields(logrus.Fields{
				logfields.NodeID:   nodeID,
				logfields.NodeName: node.Name,
			}).Debug("Allocated new node ID for node")
		}
	}

	for _, addr := range node.IPAddresses {
		n.nodeIDsByIPs[addr.IP.String()] = nodeID
	}
	return nodeID
}

// deallocateIDForNode deallocates the node ID for the given node, if it was allocated.
func (n *linuxNodeHandler) deallocateIDForNode(oldNode *nodeTypes.Node) {
	nodeID := n.nodeIDsByIPs[oldNode.IPAddresses[0].IP.String()]
	for _, addr := range oldNode.IPAddresses {
		id := n.nodeIDsByIPs[addr.IP.String()]
		if nodeID != id {
			log.WithFields(logrus.Fields{
				logfields.NodeName: oldNode.Name,
				logfields.IPAddr:   addr.IP,
			}).Errorf("Found two node IDs (%d and %d) for the same node", id, nodeID)
		}
	}

	n.deallocateNodeIDLocked(nodeID)
}

// DeallocateNodeID deallocates the given node ID, if it was allocated.
func (n *linuxNodeHandler) DeallocateNodeID(nodeID uint16) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.deallocateNodeIDLocked(nodeID)
}

func (n *linuxNodeHandler) deallocateNodeIDLocked(nodeID uint16) {
	for ip, id := range n.nodeIDsByIPs {
		if nodeID == id {
			delete(n.nodeIDsByIPs, ip)
		}
	}

	if !n.nodeIDs.Insert(idpool.ID(nodeID)) {
		log.WithField(logfields.NodeID, nodeID).Warn("Attempted to deallocate a node ID that wasn't allocated")
	}
	log.WithField(logfields.NodeID, nodeID).Debug("Deallocate node ID")
}

// DumpNodeIDs returns all node IDs and their associated IP addresses.
func (n *linuxNodeHandler) DumpNodeIDs() []*models.NodeID {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	nodeIDs := map[uint16]*models.NodeID{}
	for ip, id := range n.nodeIDsByIPs {
		if nodeID, exists := nodeIDs[id]; exists {
			nodeID.Ips = append(nodeID.Ips, ip)
			nodeIDs[id] = nodeID
		} else {
			i := int64(id)
			nodeIDs[id] = &models.NodeID{
				ID:  &i,
				Ips: []string{ip},
			}
		}
	}

	dump := make([]*models.NodeID, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		dump = append(dump, nodeID)
	}
	return dump
}
