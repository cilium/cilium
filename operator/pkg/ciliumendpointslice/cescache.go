// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"cmp"

	"k8s.io/apimachinery/pkg/util/sets"
)

type NodeName string
type EncryptionKey int
type CID string
type Labels string

// NodeData contains information about the node; the set of coreceps on
// the node and the known encryption key associated with the node.
// isKeySet indicates whether the encryption key has been explicitly set for the node
// after seeing a node update event.
type NodeData struct {
	ceps     sets.Set[CEPName]
	key      EncryptionKey
	isKeySet bool
}

func NewNodeData() *NodeData {
	return &NodeData{
		ceps:     sets.New[CEPName](),
		isKeySet: false,
	}
}

// SecIDs contains the selected CID, a set of CIDs and a set of CEPs.
// One CID from the set is selected to maintain compatibility with duplicate
// identities.
type SecIDs struct {
	selectedID CID
	ids        sets.Set[CID]
	ceps       sets.Set[CEPName]
}

func NewSecIDs() *SecIDs {
	return &SecIDs{
		ids:  sets.New[CID](),
		ceps: sets.New[CEPName](),
	}
}

// CESCache stores local CES goal state when the CES controller is running in slim mode.
// The CESCache itself is not protected by a lock; the caller should hold a lock in order
// to safely perform multi-step operations on the cache.
type CESCache struct {
	// nodeData is used to map node name to all CiliumEndpoints on the node
	// and the known encryption key associated with it
	nodeData map[NodeName]*NodeData
	// globalIdLabelsToCIDSet maps a set of labels to the CEPs and CIDs associated with it.
	// Compatible with Agent's CID management which can cause duplicate CIDs.
	globalIdLabelsToCIDSet map[Labels]*SecIDs
	// cidToGidLabels maps CID to the GID labels associated with it.
	cidToGidLabels map[CID]Labels
}

// Creates and intializes the new CESCache
func newCESCache() *CESCache {
	return &CESCache{
		nodeData:               make(map[NodeName]*NodeData),
		globalIdLabelsToCIDSet: make(map[Labels]*SecIDs),
		cidToGidLabels:         make(map[CID]Labels),
	}
}

// Update encryption key for node and return all affected CES whose CEPs are on that node,
// iff the encryption key has changed requiring reconciliation.
func (c *CESCache) insertNode(nodeName NodeName, encryptionKey EncryptionKey) []CESKey {
	if _, ok := c.nodeData[nodeName]; !ok {
		nodeData := NewNodeData()
		nodeData.setEncryptionKey(encryptionKey)
		c.nodeData[nodeName] = nodeData
		return nil
	}

	// Update the encryption key if it was not set (saw pod update before node update)
	// or if it has changed.
	if !c.nodeData[nodeName].isKeySet || c.nodeData[nodeName].key != encryptionKey {
		c.nodeData[nodeName].setEncryptionKey(encryptionKey)
		return c.getCESForCEPs(c.nodeData[nodeName].ceps)
	}
	return nil
}

// Remove node from cache and return affected CESs
func (c *CESCache) deleteNode(nodeName NodeName) []CESKey {
	if nodeData, ok := c.nodeData[nodeName]; ok {
		cesKeys := c.getCESForCEPs(nodeData.ceps)
		delete(c.nodeData, nodeName)
		return cesKeys
	}
	return nil
}

func (c *CESCache) getEndpointEncryptionKey(nodeName NodeName) (EncryptionKey, bool) {
	if nodeData, ok := c.nodeData[nodeName]; ok {
		if nodeData.isKeySet {
			return nodeData.key, true
		}
	}
	return 0, false
}

// Insert a CID into the cache and return the CESs which need to be reconciled
func (c *CESCache) insertCID(cid CID, gidLabels Labels) []CESKey {
	var cesToReconcile []CESKey
	// Clean up old state
	if oldLabels, ok := c.cidToGidLabels[cid]; ok && oldLabels != gidLabels {
		cidSet := c.globalIdLabelsToCIDSet[oldLabels]
		cidSet.ids.Delete(cid)
		// If the selectedID is the same as the CID being removed, update it to another valid CID, if it exists.
		if cidSet.selectedID == cid {
			changed := cidSet.setSelectedID("")
			if changed {
				cesToReconcile = append(cesToReconcile, c.getCESForCEPs(cidSet.ceps)...)
			}
		}
		c.cleanLabelsMapIfNoState(oldLabels)
	}
	c.cidToGidLabels[cid] = gidLabels

	secIDs := c.globalIdLabelsToCIDSet[gidLabels]
	if secIDs == nil {
		secIDs = NewSecIDs()
		c.globalIdLabelsToCIDSet[gidLabels] = secIDs
	}
	changed := secIDs.setSelectedID(cid)
	secIDs.ids.Insert(cid)
	if changed {
		cesToReconcile = append(cesToReconcile, c.getCESForCEPs(secIDs.ceps)...)
	}
	return cesToReconcile
}

// Remove CID from cache and return affected CESs
func (c *CESCache) deleteCID(cid CID) []CESKey {
	gidLabels, ok := c.cidToGidLabels[cid]
	if !ok {
		return nil
	}
	delete(c.cidToGidLabels, cid)
	if secId, ok := c.globalIdLabelsToCIDSet[gidLabels]; ok {
		var cesKeys []CESKey
		secId.ids.Delete(cid)
		if secId.selectedID == cid {
			// If the selectedID is the same as the CID being removed, update it to another valid CID, if it exists.
			changed := secId.setSelectedID("")
			if changed {
				cesKeys = append(cesKeys, c.getCESForCEPs(secId.ceps)...)
			}
		}
		c.cleanLabelsMapIfNoState(gidLabels)
		return cesKeys
	}
	return nil
}

// Return CES keys for the given CEPs. Caller must hold the cache lock.
func (c *CESCache) getCESForCEPs(ceps sets.Set[CEPName]) []CESKey {
	// TODO: Implement when CEP/CES state is tracked in cache
	return nil
}

// Clean up globalIdLabelsToCIDSet map, if no label state exists.
func (c *CESCache) cleanLabelsMapIfNoState(gidLabels Labels) {
	if secId, ok := c.globalIdLabelsToCIDSet[gidLabels]; ok {
		if secId.ceps.Len() == 0 && secId.ids.Len() == 0 {
			delete(c.globalIdLabelsToCIDSet, gidLabels)
		}
	}
}

// SetSelectedIDLocked will update the selectedID to the given CID if not set.
// If the passed CID is empty, it will find the next available CID
// and update selectedID to it, or keep as is if none available.
// Returns true if selectedID was changed.
func (s *SecIDs) setSelectedID(newCID CID) bool {
	if newCID == "" {
		for nextID := range s.ids {
			s.selectedID = nextID
			return true
		}
		return false
	}

	if !s.ids.Has(s.selectedID) {
		// selectedID was deleted from ids, force update now that valid CID is known
		s.selectedID = ""
	}
	s.selectedID = cmp.Or(s.selectedID, newCID)
	return s.selectedID == newCID
}

func (n *NodeData) setEncryptionKey(encryptionKey EncryptionKey) {
	n.key = encryptionKey
	n.isKeySet = true
}
