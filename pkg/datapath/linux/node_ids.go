// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"errors"
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

	return n.getNodeIDForIP(nodeIP)
}

func (n *linuxNodeHandler) getNodeIDForIP(nodeIP net.IP) (uint16, bool) {
	localNodeV4 := node.GetIPv4()
	localNodeV6 := node.GetIPv6()
	if localNodeV4.Equal(nodeIP) || localNodeV6.Equal(nodeIP) {
		return 0, true
	}

	if nodeID, exists := n.nodeIDsByIPs[nodeIP.String()]; exists {
		return nodeID, true
	}

	return 0, false
}

// getNodeIDForNode gets the node ID for the given node if one was allocated
// for any of the node IP addresses. If none is found, 0 is returned.
func (n *linuxNodeHandler) getNodeIDForNode(node *nodeTypes.Node) uint16 {
	nodeID := uint16(0)
	for _, addr := range node.IPAddresses {
		if id, exists := n.nodeIDsByIPs[addr.IP.String()]; exists {
			nodeID = id
		}
	}
	return nodeID
}

// allocateIDForNode allocates a new ID for the given node if one hasn't already
// been assigned. If any of the node IPs have an ID associated, then all other
// node IPs receive the same. This might happen if we allocated a node ID from
// the ipcache, where we don't have all node IPs but only one.
func (n *linuxNodeHandler) allocateIDForNode(node *nodeTypes.Node) (uint16, error) {
	var errs error

	// Did we already allocate a node ID for any IP of that node?
	nodeID := n.getNodeIDForNode(node)

	if nodeID == 0 {
		nodeID = uint16(n.nodeIDs.AllocateID())
		if nodeID == uint16(idpool.NoID) {
			log.WithField(logfields.NodeName, node.Name).Error("No more IDs available for nodes")
			errs = errors.Join(errs, fmt.Errorf("no available node ID %q", node.Name))
		} else {
			log.WithFields(logrus.Fields{
				logfields.NodeID:   nodeID,
				logfields.NodeName: node.Name,
			}).Debug("Allocated new node ID for node")
		}
	}

	for _, addr := range node.IPAddresses {
		ip := addr.IP.String()
		if _, exists := n.nodeIDsByIPs[ip]; exists {
			continue
		}
		if err := n.mapNodeID(ip, nodeID); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.NodeID: nodeID,
				logfields.IPAddr: ip,
			}).Error("Failed to map node IP address to allocated ID")
			errs = errors.Join(errs,
				fmt.Errorf("failed to map IP %q with node ID %q: %w", nodeID, nodeID, err))
		}
	}
	return nodeID, errs
}

// deallocateIDForNode deallocates the node ID for the given node, if it was allocated.
func (n *linuxNodeHandler) deallocateIDForNode(oldNode *nodeTypes.Node) error {
	var errs error
	nodeIPs := make(map[string]bool)
	nodeID := n.getNodeIDForNode(oldNode)

	// Check that all node IDs of the node had the same node ID.
	for _, addr := range oldNode.IPAddresses {
		nodeIPs[addr.IP.String()] = true
		id := n.nodeIDsByIPs[addr.IP.String()]
		if nodeID != id {
			log.WithFields(logrus.Fields{
				logfields.NodeName: oldNode.Name,
				logfields.IPAddr:   addr.IP,
			}).Errorf("Found two node IDs (%d and %d) for the same node", id, nodeID)
			errs = errors.Join(errs, fmt.Errorf("found two node IDs (%d and %d) for the same node", id, nodeID))
		}
	}

	errs = errors.Join(n.deallocateNodeIDLocked(nodeID, nodeIPs, oldNode.Name))
	return errs
}

func (n *linuxNodeHandler) deallocateNodeIDLocked(nodeID uint16, nodeIPs map[string]bool, nodeName string) error {
	var errs error
	for ip, id := range n.nodeIDsByIPs {
		if nodeID != id {
			continue
		}
		// Check that only IPs of this node had this node ID.
		if _, isIPOfOldNode := nodeIPs[ip]; !isIPOfOldNode {
			log.WithFields(logrus.Fields{
				logfields.NodeName: nodeName,
				logfields.IPAddr:   ip,
				logfields.NodeID:   id,
			}).Errorf("Found a foreign IP address with the ID of the current node")
		}

		if err := n.unmapNodeID(ip); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.NodeID: nodeID,
				logfields.IPAddr: ip,
			}).Warn("Failed to remove a node IP to node ID mapping")
		}
	}

	if !n.nodeIDs.Insert(idpool.ID(nodeID)) {
		log.WithField(logfields.NodeID, nodeID).Warn("Attempted to deallocate a node ID that wasn't allocated")
	}
	log.WithField(logfields.NodeID, nodeID).Debug("Deallocate node ID")
	return errs
}

// mapNodeID adds a node ID <> IP mapping into the local in-memory map of the
// Node Manager and in the corresponding BPF map. If any of those map updates
// fail, both are cancelled and the function returns an error.
func (n *linuxNodeHandler) mapNodeID(ip string, id uint16) error {
	if _, exists := n.nodeIDsByIPs[ip]; exists {
		return fmt.Errorf("a mapping for node IP %s already exists", ip)
	}

	nodeIP := net.ParseIP(ip)
	if nodeIP == nil {
		return fmt.Errorf("invalid node IP %s", ip)
	}

	if err := n.nodeMap.Update(nodeIP, id); err != nil {
		return err
	}

	// We only add the IP <> ID mapping in memory once we are sure it was
	// successfully added to the BPF map.
	n.nodeIDsByIPs[ip] = id
	n.nodeIPsByIDs[id] = ip

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
		delete(n.nodeIPsByIDs, id)
	}

	return nil
}

// diffAndUnmapNodeIPs takes two lists of node IP addresses: new and old ones.
// It unmaps the node IP to node ID mapping for all the old IP addresses that
// are not in the list of new IP addresses.
func (n *linuxNodeHandler) diffAndUnmapNodeIPs(oldIPs, newIPs []nodeTypes.Address) {
nextOldIP:
	for _, oldAddr := range oldIPs {
		for _, newAddr := range newIPs {
			if newAddr.IP.Equal(oldAddr.IP) {
				continue nextOldIP
			}
		}
		if err := n.unmapNodeID(oldAddr.IP.String()); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.IPAddr: oldAddr,
			}).Warn("Failed to remove a node IP to node ID mapping")
		}
	}
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

// RestoreNodeIDs restores node IDs and their associated IP addresses from the
// BPF map and into the node handler in-memory copy.
func (n *linuxNodeHandler) RestoreNodeIDs() {
	// Retrieve node IDs from the BPF map to be able to restore them.
	nodeIDs := make(map[string]uint16)
	parse := func(key *nodemap.NodeKey, val *nodemap.NodeValue) {
		address := key.IP.String()
		if key.Family == bpf.EndpointKeyIPv4 {
			address = net.IP(key.IP[:net.IPv4len]).String()
		}
		nodeIDs[address] = val.NodeID
	}
	if err := n.nodeMap.IterateWithCallback(parse); err != nil {
		log.WithError(err).Error("Failed to dump content of node map")
		return
	}

	n.registerNodeIDAllocations(nodeIDs)
	log.Infof("Restored %d node IDs from the BPF map", len(nodeIDs))
}

func (n *linuxNodeHandler) registerNodeIDAllocations(allocatedNodeIDs map[string]uint16) {
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
		n.nodeIPsByIDs[id] = ip // reverse mapping for all ip, id pairs
		if _, exists := nodeIDs[id]; !exists {
			nodeIDs[id] = struct{}{}
			if !n.nodeIDs.Remove(idpool.ID(id)) {
				// This is just a sanity check. It should never happen as we
				// have checked that we start with a full idpool (0 allocated
				// node IDs) and then only remove them from the idpool if they
				// were already removed.
				log.WithField(logfields.NodeID, id).Error("Node ID was already allocated")
			}
		}
	}
}
