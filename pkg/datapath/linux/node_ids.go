// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"errors"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
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
	return n.nodeIPsByIDs[nodeID].ip
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

	// TODO: Improve this
	for addr, nid := range n.nodeIDsByIPs {
		if addr.ip == nodeIP.String() {
			return nid, true
		}
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
			log.WithField(logfields.NodeName, node.Name).Error("No more IDs available for nodes")
			// If we failed to allocate nodeID, don't map any IP to 0 nodeID.
			// This causes later errors like "Found a foreign IP address with the ID of the current node"
			// so we make early return here.
			return nodeID, fmt.Errorf("no available node ID %q", node.Name)
		} else {
			log.WithFields(logrus.Fields{
				logfields.NodeID:   nodeID,
				logfields.NodeName: node.Name,
				logfields.SPI:      node.EncryptionKey,
			}).Debug("Allocated new node ID for node")
		}
	}

	for _, addr := range node.IPAddresses {
		mapAddrType, err := addrTypeToEnum(addr.Type)
		if err != nil {
			log.WithError(err).Error("unexpected node address type encountered, cannot perform mapping")
			// todo: impact?...
			continue
		}

		ip := addr.IP.String()
		na := nodeAddress{
			ip:       ip,
			addrType: mapAddrType,
		}
		if _, exists := n.nodeIDsByIPs[na]; exists {
			if !SPIChanged {
				continue
			}
		}

		if err := n.mapNodeID(ip, nodeID, node.EncryptionKey, mapAddrType); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.NodeID: nodeID,
				logfields.IPAddr: ip,
				logfields.SPI:    node.EncryptionKey,
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
		mapAddrType, err := addrTypeToEnum(addr.Type)
		if err != nil {
			log.WithError(err).Error("unexpected node address type encountered, cannot perform mapping")
			// todo: impact?...
			continue
		}
		na := nodeAddress{
			ip:       addr.IP.String(),
			addrType: mapAddrType,
		}
		nodeIPs[addr.IP.String()] = true
		id := n.nodeIDsByIPs[na]
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
	for addr, id := range n.nodeIDsByIPs {
		if nodeID != id {
			continue
		}
		// Check that only IPs of this node had this node ID.
		if _, isIPOfOldNode := nodeIPs[addr.ip]; !isIPOfOldNode {
			log.WithFields(logrus.Fields{
				logfields.NodeName: nodeName,
				logfields.IPAddr:   addr.ip,
				logfields.NodeID:   id,
			}).Errorf("Found a foreign IP address with the ID of the current node")
		}

		if err := n.unmapNodeID(addr.ip, addr.addrType); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.NodeID: nodeID,
				logfields.IPAddr: addr.ip,
			}).Warn("Failed to remove a node IP to node ID mapping")
		}
	}

	if !n.nodeIDs.Insert(idpool.ID(nodeID)) {
		log.WithField(logfields.NodeID, nodeID).Warn("Attempted to deallocate a node ID that wasn't allocated")
	}
	log.WithField(logfields.NodeID, nodeID).Debug("Deallocate node ID")
	return errs
}

func addrTypeToEnum(ad addressing.AddressType) (nodemap.AddressType, error) {
	switch ad {
	case addressing.NodeExternalIP:
		return nodemap.NodeExternalIP, nil
	case addressing.NodeInternalIP:
		return nodemap.NodeCiliumInternalIP, nil
	case addressing.NodeCiliumInternalIP:
		return nodemap.NodeCiliumInternalIP, nil
	default:
		return 0, fmt.Errorf("invalid node address type %v", ad)
	}
}

// mapNodeID adds a node ID <> IP mapping into the local in-memory map of the
// Node Manager and in the corresponding BPF map. If any of those map updates
// fail, both are cancelled and the function returns an error.
func (n *linuxNodeHandler) mapNodeID(ip string, id uint16, SPI uint8, addrType nodemap.AddressType) error {
	nodeIP := net.ParseIP(ip)
	if nodeIP == nil {
		return fmt.Errorf("invalid node IP %s", ip)
	}

	// We only add the IP <> ID mapping in memory once we are sure it was
	// successfully added to the BPF map.
	//
	// We need to avoid situations where we're adding a ip -> id mapping
	// such that two different node IDs to the same IP.
	na := nodeAddress{
		ip:       ip,
		addrType: addrType,
	}

	var errs error
	// Ensure that the mappings remain bijective for {ip, addressType} <-> {nodeID}
	// by removing any stale mappings.
	//
	// Without this check, we would overwrite anything in n.nodeIDsByIPs with the new
	// id value, if there is already such a mapping, we have to *completely* remove
	// it prior to proceeding.
	// {nodeID} -> {ip, addrType}
	// {ip, addrType} -> {nodeID}
	if _, exists := n.nodeIDsByIPs[na]; exists {
		parsed := net.ParseIP(na.ip)
		toDeleteID := n.nodeIDsByIPs[na]
		log.WithFields(logrus.Fields{
			"ip":   na.ip,
			"type": na.addrType,
			"id":   toDeleteID,
		}).Info("removed old node_id mapping")
		delete(n.nodeIDsByIPs, na)
		delete(n.nodeIPsByIDs, toDeleteID)
		if err := n.nodeMap.Delete(parsed, na.addrType); err != nil {
			// If this is a real failure, do a best effort and continue.
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = errors.Join(errs, err)
			}
		}
	}

	if err := n.nodeMap.Update(nodeIP, addrType, id, SPI); err != nil {
		return err
	}

	// Q: what happens during a node with the same ip but for different types.

	// 1. IP -> ID : Only one IP can exist
	// The idea is that these two maps can only represent a bijection.
	//
	// NodeA maps to many IP:
	// -> In this case the first map will have many such mappings, but
	// 	the ID -> IP map will only have the last one updated.
	n.nodeIDsByIPs[na] = id
	n.nodeIPsByIDs[id] = na

	return nil
}

// unmapNodeID removes a node ID <> IP mapping from the local in-memory map of
// the Node Manager and from the corresponding BPF map. If any of those map
// updates fail, it returns an error; in such a case, both are cancelled.
func (n *linuxNodeHandler) unmapNodeID(ip string, addressType nodemap.AddressType) error {
	na := nodeAddress{
		ip:       ip,
		addrType: addressType,
	}
	// Check error cases first, to avoid having to cancel anything.
	if _, exists := n.nodeIDsByIPs[na]; !exists {
		return fmt.Errorf("cannot remove IP %s from node ID map as it doesn't exist", ip)
	}
	nodeIP := net.ParseIP(ip)
	if nodeIP == nil {
		return fmt.Errorf("invalid node IP %s", ip)
	}

	if err := n.nodeMap.Delete(nodeIP, addressType); err != nil {
		return err
	}
	if id, exists := n.nodeIDsByIPs[na]; exists {
		delete(n.nodeIDsByIPs, na)
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
		addrType, err := addrTypeToEnum(oldAddr.Type)
		if err != nil {
			log.WithError(err).Error("BUG: unexpected node addr type, annot diff and unmap nodes")
		}
		if err := n.unmapNodeID(oldAddr.IP.String(), addrType); err != nil {
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
	for addr, id := range n.nodeIDsByIPs {
		if nodeID, exists := nodeIDs[id]; exists {
			nodeID.Ips = append(nodeID.Ips, addr.ip)
			nodeIDs[id] = nodeID
		} else {
			i := int64(id)
			nodeIDs[id] = &models.NodeID{
				ID:  &i,
				Ips: []string{addr.ip},
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
	nodeValues := make(map[nodeAddress]*nodemap.NodeValueV2)
	incorrectNodeIDs := sets.New[nodeAddress]()
	parse := func(key *nodemap.NodeKey, val *nodemap.NodeValueV2) {
		var address string
		if key.Family == bpf.EndpointKeyIPv4 {
			address = net.IP(key.IP[:net.IPv4len]).String()
		}
		na := nodeAddress{
			ip:       address,
			addrType: key.Type,
		}
		if val.NodeID == 0 {
			incorrectNodeIDs[na] = struct{}{}
		}
		nodeValues[na] = &nodemap.NodeValueV2{
			NodeID: val.NodeID,
			SPI:    val.SPI,
		}
	}

	if err := n.nodeMap.IterateWithCallback(parse); err != nil {
		log.WithError(err).Error("Failed to dump content of node map")
		return
	}

	n.registerNodeIDAllocations(nodeValues)
	if len(incorrectNodeIDs) > 0 {
		log.Warnf("Removing %d incorrect node IP to node ID mappings from the BPF map", len(incorrectNodeIDs))
	}
	for addr := range incorrectNodeIDs {
		if err := n.unmapNodeID(addr.ip, addr.addrType); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.IPAddr: addr.ip,
				logfields.Type:   addr.addrType,
			}).Warn("Failed to remove a incorrect node IP to node ID mapping")
		}
	}
	log.Infof("Restored %d node IDs from the BPF map", len(nodeValues))
}

// Why do we need to partition by the address type?
func (n *linuxNodeHandler) registerNodeIDAllocations(allocatedNodeIDs map[nodeAddress]*nodemap.NodeValueV2) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if len(n.nodeIDsByIPs) > 0 {
		// If this happens, we likely have a bug in the startup logic and
		// restored node IDs too late (after new node IDs were allocated).
		log.Error("The node manager already contains node IDs")
	}

	// The node manager holds both a map of nodeIP=>nodeID and a pool of ID for
	// the allocation of node IDs. Not only do we need to update the map,
	nodeIDs := make(map[uint16]struct{})
	IDsByIPs := make(map[nodeAddress]uint16)
	IPsByIDs := make(map[uint16]nodeAddress)
	for addr, val := range allocatedNodeIDs {
		id := val.NodeID
		// The problem is that we don't store addresstypes in the bpf map, so how could
		// we restore these?
		IDsByIPs[addr] = id
		IPsByIDs[id] = addr
		// ...but we also need to remove any restored nodeID from the pool of IDs
		// available for allocation.
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

	n.nodeIDsByIPs = IDsByIPs
	n.nodeIPsByIDs = IPsByIDs
}
