// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"errors"
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/util/sets"

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

	// Otherwise, return one of the IPs matching the given ID.
	for ip := range n.nodeIPsByIDs[nodeID] {
		return ip
	}

	return ""
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
func (n *linuxNodeHandler) allocateIDForNode(oldNode *nodeTypes.Node, node *nodeTypes.Node) (uint16, error) {
	var errs error

	// Did we already allocate a node ID for any IP of that node?
	nodeID := n.getNodeIDForNode(node)

	// Perform an SPI refresh opportunistically.
	// This avoids the scenario where the agent may have been down and didn't
	// catch a NodeDelete event, leaving a stale IP address in the map.
	var SPIChanged bool = true
	if oldNode != nil {
		SPIChanged = (oldNode.EncryptionKey != node.EncryptionKey)
	}

	if nodeID == 0 {
		nodeID = uint16(n.nodeIDs.AllocateID())
		if nodeID == uint16(idpool.NoID) {
			n.log.Error("No more IDs available for nodes",
				logfields.NodeName, node.Name,
			)
			// If we failed to allocate nodeID, don't map any IP to 0 nodeID.
			// This causes later errors like "Found a foreign IP address with the ID of the current node"
			// so we make early return here.
			return nodeID, fmt.Errorf("no available node ID %q", node.Name)
		} else {
			n.log.Debug("Allocated new node ID for node",
				logfields.NodeID, nodeID,
				logfields.NodeName, node.Name,
				logfields.SPI, node.EncryptionKey,
			)
		}
	}

	for _, addr := range node.IPAddresses {
		ip := addr.IP.String()
		if _, exists := n.nodeIDsByIPs[ip]; exists {
			if !SPIChanged {
				continue
			}
		}
		if err := n.mapNodeID(ip, nodeID, node.EncryptionKey); err != nil {
			n.log.Error("Failed to map node IP address to allocated ID",
				logfields.Error, err,
				logfields.NodeID, nodeID,
				logfields.IPAddr, ip,
				logfields.SPI, node.EncryptionKey,
			)
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
			n.log.Error("Found two node IDs for the same node",
				"first", id, "second", nodeID,
				logfields.NodeName, oldNode.Name,
				logfields.IPAddr, addr.IP,
			)
			errs = errors.Join(errs, fmt.Errorf("found two node IDs (%d and %d) for the same node", id, nodeID))
		}
	}

	errs = errors.Join(n.deallocateNodeIDLocked(nodeID, nodeIPs, oldNode.Name))
	return errs
}

func (n *linuxNodeHandler) deallocateNodeIDLocked(nodeID uint16, nodeIPs map[string]bool, nodeName string) error {
	var errs error
	for ip := range n.nodeIPsByIDs[nodeID] {
		// Check that only IPs of this node had this node ID.
		if _, isIPOfOldNode := nodeIPs[ip]; !isIPOfOldNode {
			n.log.Error("Found a foreign IP address with the ID of the current node",
				logfields.NodeName, nodeName,
				logfields.IPAddr, ip,
				logfields.NodeID, nodeID,
			)
		}

		if err := n.unmapNodeID(ip); err != nil {
			n.log.Warn("Failed to remove a node IP to node ID mapping",
				logfields.Error, err,
				logfields.NodeID, nodeID,
				logfields.IPAddr, ip,
			)
		}
	}

	if !n.nodeIDs.Insert(idpool.ID(nodeID)) {
		n.log.Warn("Attempted to deallocate a node ID that wasn't allocated",
			logfields.NodeID, nodeID,
		)
	}
	n.log.Debug("Deallocated node ID", logfields.NodeID, nodeID)
	return errs
}

// mapNodeID adds a node ID <> IP mapping into the local in-memory map of the
// Node Manager and in the corresponding BPF map. If any of those map updates
// fail, both are cancelled and the function returns an error.
func (n *linuxNodeHandler) mapNodeID(ip string, id uint16, SPI uint8) error {
	nodeIP := net.ParseIP(ip)
	if nodeIP == nil {
		return fmt.Errorf("invalid node IP %s", ip)
	}

	if err := n.nodeMap.Update(nodeIP, id, SPI); err != nil {
		return err
	}

	// We only add the IP <> ID mapping in memory once we are sure it was
	// successfully added to the BPF map.
	n.nodeIDsByIPs[ip] = id
	setIPsByIDsMapping(n.nodeIPsByIDs, id, ip)

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

		n.nodeIPsByIDs[id].Delete(ip)
		if n.nodeIPsByIDs[id].Len() == 0 {
			delete(n.nodeIPsByIDs, id)
		}
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
			n.log.Warn("Failed to remove a node IP to node ID mapping",
				logfields.Error, err,
				logfields.IPAddr, oldAddr,
			)
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
	nodeValues := make(map[string]*nodemap.NodeValueV2)
	incorrectNodeIDs := make(map[string]struct{})
	parse := func(key *nodemap.NodeKey, val *nodemap.NodeValueV2) {
		address := key.IP.String()
		if key.Family == bpf.EndpointKeyIPv4 {
			address = net.IP(key.IP[:net.IPv4len]).String()
		}
		if val.NodeID == 0 {
			incorrectNodeIDs[address] = struct{}{}
		}
		nodeValues[address] = &nodemap.NodeValueV2{
			NodeID: val.NodeID,
			SPI:    val.SPI,
		}
	}

	if err := n.nodeMap.IterateWithCallback(parse); err != nil {
		n.log.Error("Failed to dump content of node map",
			logfields.Error, err)
		return
	}

	n.registerNodeIDAllocations(nodeValues)
	if len(incorrectNodeIDs) > 0 {
		n.log.Warn("Removing incorrect node IP to node ID mappings from the BPF map",
			logfields.Count, len(incorrectNodeIDs))
	}
	for ip := range incorrectNodeIDs {
		if err := n.unmapNodeID(ip); err != nil {
			n.log.Warn("Failed to remove a incorrect node IP to node ID mapping",
				logfields.Error, err,
				logfields.IPAddr, ip,
			)
		}
	}
	n.log.Info("Restored node IDs from the BPF map",
		logfields.Count, len(nodeValues))
}

func (n *linuxNodeHandler) registerNodeIDAllocations(allocatedNodeIDs map[string]*nodemap.NodeValueV2) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if len(n.nodeIDsByIPs) > 0 {
		// If this happens, we likely have a bug in the startup logic and
		// restored node IDs too late (after new node IDs were allocated).
		n.log.Error("The node manager already contains node IDs")
	}

	// The node manager holds both a map of nodeIP=>nodeID and a pool of ID for
	// the allocation of node IDs. Not only do we need to update the map,
	nodeIDs := make(map[uint16]struct{})
	IDsByIPs := make(map[string]uint16)
	IPsByIDs := make(map[uint16]sets.Set[string])
	for ip, val := range allocatedNodeIDs {
		id := val.NodeID
		IDsByIPs[ip] = id
		setIPsByIDsMapping(IPsByIDs, id, ip)
		// ...but we also need to remove any restored nodeID from the pool of IDs
		// available for allocation.
		if _, exists := nodeIDs[id]; !exists {
			nodeIDs[id] = struct{}{}
			if !n.nodeIDs.Remove(idpool.ID(id)) {
				// This is just a sanity check. It should never happen as we
				// have checked that we start with a full idpool (0 allocated
				// node IDs) and then only remove them from the idpool if they
				// were already removed.
				n.log.Error("Node ID was already allocated",
					logfields.NodeID, id,
				)
			}
		}
	}

	n.nodeIDsByIPs = IDsByIPs
	n.nodeIPsByIDs = IPsByIDs
}

func setIPsByIDsMapping(nodeIPsByIDs map[uint16]sets.Set[string], id uint16, ip string) {
	ips, ok := nodeIPsByIDs[id]
	if !ok {
		ips = sets.New[string]()
		nodeIPsByIDs[id] = ips
	}
	ips.Insert(ip)
}
