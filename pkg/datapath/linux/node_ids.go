// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

const (
	minNodeID = 1
	maxNodeID = idpool.ID(^uint16(0))
)

var (
	localNodeID = nodeID{
		id:     0,
		refcnt: 1,
	}
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

	n.mutex.Lock()
	defer n.mutex.Unlock()

	if nodeID := n.getNodeIDForIP(nodeIP); nodeID != nil {
		nodeID.refcnt++
		return nodeID.id
	}

	id := uint16(n.nodeIDs.AllocateID())
	if id == uint16(idpool.NoID) {
		log.Error("No more IDs available for nodes")
		return id
	} else {
		log.WithFields(logrus.Fields{
			logfields.NodeID: id,
			logfields.IPAddr: nodeIP,
		}).Debug("Allocated new node ID for node IP address")
	}
	nodeID := &nodeID{
		id:     id,
		refcnt: 1,
	}
	if err := n.mapNodeID(nodeIP.String(), nodeID); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.NodeID: nodeID,
			logfields.IPAddr: nodeIP.String(),
		}).Error("Failed to map node IP address to allocated ID")
	}
	return nodeID.id
}

func (n *linuxNodeHandler) GetNodeIP(nodeID uint16) string {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	// Check for local node ID explicitly as local node IPs are not in our maps!
	if nodeID == 0 {
		// Returns local node's IPv4 address if available, IPv6 address otherwise.
		return node.GetCiliumEndpointNodeIP()
	}
	return n.nodeIPsByIDs[nodeID]
}

func (n *linuxNodeHandler) GetNodeID(nodeIP net.IP) (uint16, bool) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	nodeID := n.getNodeIDForIP(nodeIP)
	if nodeID == nil {
		return 0, false
	}
	return nodeID.id, true
}

func (n *linuxNodeHandler) getNodeIDForIP(nodeIP net.IP) *nodeID {
	localNodeV4 := node.GetIPv4()
	localNodeV6 := node.GetIPv6()
	if localNodeV4.Equal(nodeIP) || localNodeV6.Equal(nodeIP) {
		return &localNodeID
	}

	if nodeID, exists := n.nodeIDsByIPs[nodeIP.String()]; exists {
		return nodeID
	}

	return nil
}

// getNodeIDForNode gets the node ID for the given node if one was allocated
// for any of the node IP addresses. If none is found, 0 is returned.
func (n *linuxNodeHandler) getNodeIDForNode(node *nodeTypes.Node) *nodeID {
	for _, addr := range node.IPAddresses {
		if nodeID, exists := n.nodeIDsByIPs[addr.IP.String()]; exists {
			return nodeID
		}
	}
	return nil
}

func (n *linuxNodeHandler) deleteNodeIPs(oldIPs, newIPs []nodeTypes.Address) {
	for _, oldAddr := range oldIPs {
		found := false
		for _, newAddr := range newIPs {
			if newAddr.IP.String() == oldAddr.IP.String() {
				found = true
				break
			}
		}
		if !found {
			if err := n.unmapNodeID(oldAddr.IP.String()); err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.IPAddr: oldAddr,
				}).Warn("DeleteNodeIPS failed to remove a node IP to node ID mapping")
			}
		}
	}
}

// allocateIDForNode allocates a new ID for the given node if one hasn't already
// been assigned. If any of the node IPs have an ID associated, then all other
// node IPs receive the same. This might happen if we allocated a node ID from
// the ipcache, where we don't have all node IPs but only one.
func (n *linuxNodeHandler) allocateIDForNode(node *nodeTypes.Node) uint16 {
	// Did we already allocate a node ID for any IP of that node?
	nID := n.getNodeIDForNode(node)

	if nID == nil {
		id := uint16(n.nodeIDs.AllocateID())
		if id == uint16(idpool.NoID) {
			log.WithField(logfields.NodeName, node.Name).Error("No more IDs available for nodes")
		} else {
			log.WithFields(logrus.Fields{
				logfields.NodeID:   id,
				logfields.NodeName: node.Name,
			}).Debug("Allocated new node ID for node")
		}
		nID = &nodeID{
			id:     id,
			refcnt: 1,
		}
	} else {
		nID.refcnt++
	}

	for _, addr := range node.IPAddresses {
		ip := addr.IP.String()
		if _, exists := n.nodeIDsByIPs[ip]; exists {
			continue
		}
		if err := n.mapNodeID(ip, nID); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.NodeID: nID.id,
				logfields.IPAddr: ip,
			}).Error("Failed to map node IP address to allocated ID")
		}
	}
	return nID.id
}

// deallocateIDForNode deallocates the node ID for the given node, if it was allocated.
func (n *linuxNodeHandler) deallocateIDForNode(oldNode *nodeTypes.Node) {
	nodeID := n.getNodeIDForNode(oldNode)
	if nodeID == nil {
		log.WithFields(logrus.Fields{
			logfields.NodeName: oldNode.Name,
		}).Warn("deallocate ID for node that does not have an existing ID")
		return
	}

	for _, addr := range oldNode.IPAddresses {
		id, exists := n.nodeIDsByIPs[addr.IP.String()]
		if !exists {
			log.WithFields(logrus.Fields{
				logfields.NodeName: oldNode.Name,
				logfields.IPAddr:   addr.IP,
			}).Errorf("deallocateIDForNode with node IP that wasn't mapped to ID")
			continue
		}
		if nodeID.id != id.id {
			log.WithFields(logrus.Fields{
				logfields.NodeName: oldNode.Name,
				logfields.IPAddr:   addr.IP,
			}).Errorf("Found two node IDs (%d and %d) for the same node", id, nodeID)
		}
	}

	n.deallocateNodeIDLocked(nodeID)
}

// DeallocateNodeID deallocates the given node ID, if it was allocated.
func (n *linuxNodeHandler) DeallocateNodeID(nodeIP net.IP) {
	localNode := node.GetIPv4()
	if localNode.Equal(nodeIP) {
		log.WithFields(logrus.Fields{
			logfields.IPAddr: nodeIP,
		}).Warning("Attempt to deallocate local node ID")
		return
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	nodeID, exists := n.nodeIDsByIPs[nodeIP.String()]
	if !exists {
		log.WithFields(logrus.Fields{
			logfields.IPAddr: nodeIP,
		}).Warning("Attempt to deallocate node ID for unknown IP")
		return
	}

	n.deallocateNodeIDLocked(nodeID)
}

func (n *linuxNodeHandler) deallocateNodeIDLocked(nodeID *nodeID) {
	if nodeID.refcnt < 1 {
		log.WithFields(logrus.Fields{
			logfields.NodeID: nodeID.id,
		}).Warning("Attempt to deallocate node ID with refcnt <1")
	}

	nodeID.refcnt--
	if nodeID.refcnt != 0 {
		return
	}

	for ip, id := range n.nodeIDsByIPs {
		if nodeID.id == id.id {
			if err := n.unmapNodeID(ip); err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.NodeID: nodeID,
					logfields.IPAddr: ip,
				}).Warn("Failed to remove a node IP to node ID mapping")
			}
		}
	}

	if !n.nodeIDs.Insert(idpool.ID(nodeID.id)) {
		log.WithField(logfields.NodeID, nodeID.id).Warn("Attempted to deallocate a node ID that wasn't allocated")
	}
	log.WithField(logfields.NodeID, nodeID.id).Debug("Deallocate node ID")
}

// mapNodeID adds a node ID <> IP mapping into the local in-memory map of the
// Node Manager and in the corresponding BPF map. If any of those map updates
// fail, both are cancelled and the function returns an error.
func (n *linuxNodeHandler) mapNodeID(ip string, id *nodeID) error {
	if _, exists := n.nodeIDsByIPs[ip]; exists {
		return fmt.Errorf("a mapping for node IP %s already exists", ip)
	}

	nodeIP := net.ParseIP(ip)
	if nodeIP == nil {
		return fmt.Errorf("invalid node IP %s", ip)
	}

	if err := n.nodeMap.Update(nodeIP, id.id); err != nil {
		return err
	}

	// We only add the IP <> ID mapping in memory once we are sure it was
	// successfully added to the BPF map.
	n.nodeIDsByIPs[ip] = id
	n.nodeIPsByIDs[id.id] = ip

	return nil
}

// unmapNodeID removes a node ID <> IP mapping from the local in-memory map of
// the Node Manager and from the corresponding BPF map. If any of those map
// updates fail, it returns an error; in such a case, both are cancelled.
func (n *linuxNodeHandler) unmapNodeID(ip string) error {
	// Check error cases first, to avoid having to cancel anything.
	if _, exists := n.nodeIDsByIPs[ip]; !exists {
		return fmt.Errorf("cannot remove IP %s from node ID map as it doesn't exist", ip)
	}
	nodeIP := net.ParseIP(ip)
	if nodeIP == nil {
		return fmt.Errorf("invalid node IP %s", ip)
	}

	if err := n.nodeMap.Delete(nodeIP); err != nil {
		return err
	}
	if id, exists := n.nodeIDsByIPs[ip]; exists {
		delete(n.nodeIDsByIPs, ip)
		delete(n.nodeIPsByIDs, id.id)
	}

	return nil
}

// DumpNodeIDs returns all node IDs and their associated IP addresses.
func (n *linuxNodeHandler) DumpNodeIDs() []*models.NodeID {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	nodeIDs := map[uint16]*models.NodeID{}
	for ip, id := range n.nodeIDsByIPs {
		if nodeID, exists := nodeIDs[id.id]; exists {
			nodeID.Ips = append(nodeID.Ips, ip)
			nodeIDs[id.id] = nodeID
		} else {
			i := int64(id.id)
			nodeIDs[id.id] = &models.NodeID{
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

// RestoreNodeIDs restores node IDs and their associated IP addresses from the
// BPF map and into the node handler in-memory copy.
func (n *linuxNodeHandler) RestoreNodeIDs() {
	// Retrieve node IDs from the BPF map to be able to restore them.
	nodeIDs := make(map[string]*nodeID)
	parse := func(key *nodemap.NodeKey, val *nodemap.NodeValue) {
		address := key.IP.String()
		if key.Family == bpf.EndpointKeyIPv4 {
			address = net.IP(key.IP[:net.IPv4len]).String()
		}
		nid := &nodeID{
			id:     val.NodeID,
			refcnt: 1,
		}
		nodeIDs[address] = nid
	}
	if err := n.nodeMap.IterateWithCallback(parse); err != nil {
		log.WithError(err).Error("Failed to dump content of node map")
		return
	}

	n.registerNodeIDAllocations(nodeIDs)
	log.Infof("Restored %d node IDs from the BPF map", len(nodeIDs))
}

func (n *linuxNodeHandler) registerNodeIDAllocations(allocatedNodeIDs map[string]*nodeID) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if len(n.nodeIDsByIPs) > 0 {
		// If this happens, we likely have a bug in the startup logic and
		// restored node IDs too late (after new node IDs were allocated).
		log.Error("The node manager already contains node IDs")
	}

	// The node manager holds both a map of nodeIP=>nodeID and a pool of ID for
	// the allocation of node IDs. Not only do we need to update the map,
	n.nodeIDsByIPs = allocatedNodeIDs
	n.nodeIPsByIDs = map[uint16]string{}
	// ...but we also need to remove any restored nodeID from the pool of IDs
	// available for allocation.
	nodeIDs := make(map[uint16]struct{})
	for ip, id := range allocatedNodeIDs {
		n.nodeIPsByIDs[id.id] = ip // reverse mapping for all ip, id pairs
		if _, exists := nodeIDs[id.id]; !exists {
			nodeIDs[id.id] = struct{}{}
			if !n.nodeIDs.Remove(idpool.ID(id.id)) {
				// This is just a sanity check. It should never happen as we
				// have checked that we start with a full idpool (0 allocated
				// node IDs) and then only remove them from the idpool if they
				// were already removed.
				log.WithField(logfields.NodeID, id).Error("Node ID was already allocated")
			}
		}
	}
}
