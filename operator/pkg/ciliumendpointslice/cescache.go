// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"cmp"
	"maps"
	"slices"

	"k8s.io/apimachinery/pkg/util/sets"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

type NodeName string
type EncryptionKey int
type CID string
type Labels string

type CESCacher interface {
	hasCESName(cesName CESName) bool
	insertCES(cesName CESName, ns string)
	getAllCESs() []CESName
	countCEPsInCES(ces CESName) int
	getCESNamespace(name CESName) string
}

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

// CEPData contains the CES, node and labels associated with the corecep.
type CEPData struct {
	ces    CESName
	node   NodeName
	labels Labels
}

// CESCache stores local CES goal state when the CES controller is running in slim mode.
// The CESCache itself is not protected by a lock; the caller should hold a lock in order
// to safely perform multi-step operations on the cache.
type CESCache struct {
	// cepData is used to map CiliumEndpoint name to the CiliumEndpointSlice, Node and
	// Labels associated with it.
	cepData map[CEPName]*CEPData
	// cesData is used to map CiliumEndpointSlice name to all CiliumEndpoints names it contains
	// and the namespace associated with it
	cesData map[CESName]*CESData
	// nsData is used to map namespaces to all CiliumEndpointSlices in them
	nsData map[string]sets.Set[CESName]
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
		cepData:                make(map[CEPName]*CEPData),
		cesData:                make(map[CESName]*CESData),
		nsData:                 make(map[string]sets.Set[CESName]),
		nodeData:               make(map[NodeName]*NodeData),
		globalIdLabelsToCIDSet: make(map[Labels]*SecIDs),
		cidToGidLabels:         make(map[CID]Labels),
	}
}

// Add CEP to cache, map to CES name and node name
func (c *CESCache) addCEP(cepName CEPName, cesName CESName, nodeName NodeName, gidLabels Labels) {
	c.updateCEPInCache(cepName, nodeName, gidLabels, cesName)
}

// Updates known information about CEP in local cache, without CID information.
// Handles the cases where the CEP node or labels may have changed.
func (c *CESCache) updateCEPInCache(cepName CEPName, nodeName NodeName, gidLabels Labels, cesName CESName) {
	c.clearStaleState(cepName, nodeName, gidLabels, cesName)

	c.cepData[cepName] = &CEPData{
		ces:    cesName,
		node:   nodeName,
		labels: gidLabels,
	}

	c.cesData[cesName].ceps.Insert(cepName)

	if _, ok := c.nodeData[nodeName]; !ok {
		c.nodeData[nodeName] = NewNodeData()
	}
	c.nodeData[nodeName].ceps.Insert(cepName)

	if _, ok := c.globalIdLabelsToCIDSet[gidLabels]; !ok {
		c.globalIdLabelsToCIDSet[gidLabels] = NewSecIDs()
		// selectedID will be set when the first CID is inserted.
	}
	c.globalIdLabelsToCIDSet[gidLabels].ceps.Insert(cepName)
}

// Helper to clear stale state when CEP is updated and remove old mappings.
func (c *CESCache) clearStaleState(cepName CEPName, newNodeName NodeName, newGIDLabels Labels, newCESName CESName) {
	if cepData, ok := c.cepData[cepName]; ok {
		// If CEP was previously mapped to different CES, clear.
		if oldCES := cepData.ces; oldCES != newCESName {
			c.cesData[oldCES].ceps.Delete(cepName)
		}

		// If CEP was previously mapped to different node, clear.
		if oldNode := cepData.node; oldNode != newNodeName {
			c.nodeData[oldNode].ceps.Delete(cepName)
		}

		// If CEP was previously mapped to different labels, clear.
		if oldLabels := cepData.labels; oldLabels != newGIDLabels {
			c.globalIdLabelsToCIDSet[oldLabels].ceps.Delete(cepName)
			c.cleanLabelsMapIfNoState(oldLabels)
		}
	}
}

// Remove the CEP entry from mappings
func (c *CESCache) deleteCEP(cepName CEPName) {
	if cepData, ok := c.cepData[cepName]; ok {
		if _, ok := c.nodeData[cepData.node]; ok {
			c.nodeData[cepData.node].ceps.Delete(cepName)
		}

		if _, ok := c.globalIdLabelsToCIDSet[cepData.labels]; ok {
			c.globalIdLabelsToCIDSet[cepData.labels].ceps.Delete(cepName)
			c.cleanLabelsMapIfNoState(cepData.labels)
		}

		c.cesData[cepData.ces].ceps.Delete(cepName)
	}
	delete(c.cepData, cepName)
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

// Initializes mapping structure for CES
func (c *CESCache) insertCES(cesName CESName, ns string) {
	// Update CES namespace if it has changed
	if cesData, ok := c.cesData[cesName]; ok {
		if cesData.ns != ns {
			c.nsData[cesData.ns].Delete(cesName)
			if c.nsData[cesData.ns].Len() == 0 {
				delete(c.nsData, cesData.ns)
			}

			cesData.ns = ns
		}
	} else {
		c.cesData[cesName] = NewCESData(ns)
	}

	if _, ok := c.nsData[ns]; !ok {
		c.nsData[ns] = sets.New[CESName]()
	}
	c.nsData[ns].Insert(cesName)
}

// Remove mapping structure for CES
func (c *CESCache) deleteCES(cesName CESName) {
	if cesData, ok := c.cesData[cesName]; ok {
		if cesSet, ok := c.nsData[cesData.ns]; ok {
			cesSet.Delete(cesName)
			if cesSet.Len() == 0 {
				delete(c.nsData, cesData.ns)
			}
		}
	}
	delete(c.cesData, cesName)
}

// Return CES keys for the given CEPs. Caller must hold the cache lock.
func (c *CESCache) getCESForCEPs(ceps sets.Set[CEPName]) []CESKey {
	cesKeys := sets.Set[CESKey]{}
	for cepName := range ceps {
		cesName, ok := c.getCESName(cepName)
		if ok {
			cesNs := c.getCESNamespace(cesName)
			cesKeys.Insert(NewCESKey(cesName.string(), cesNs))
		}
	}
	return cesKeys.UnsortedList()
}

// Clean up globalIdLabelsToCIDSet map, if no label state exists.
func (c *CESCache) cleanLabelsMapIfNoState(gidLabels Labels) {
	if secId, ok := c.globalIdLabelsToCIDSet[gidLabels]; ok {
		if secId.ceps.Len() == 0 && secId.ids.Len() == 0 {
			delete(c.globalIdLabelsToCIDSet, gidLabels)
		}
	}
}

// Return total number of CEPs mapped to the given CES
func (c *CESCache) countCEPsInCES(ces CESName) int {
	if cesData, ok := c.cesData[ces]; ok {
		return cesData.ceps.Len()
	}
	return 0
}

// Return CEP Names mapped to the given CES
func (c *CESCache) getCEPsInCES(ces CESName) []CEPName {
	if cesData, ok := c.cesData[ces]; ok {
		return cesData.ceps.UnsortedList()
	}
	return nil
}

// Return if the given CES is present in cache
func (c *CESCache) hasCESName(cesName CESName) bool {
	_, ok := c.cesData[cesName]
	return ok
}

// Return names of all CESs.
func (c *CESCache) getAllCESs() []CESName {
	return slices.Collect(maps.Keys(c.cesData))
}

// Return the namespace of the given CES
func (c *CESCache) getCESNamespace(name CESName) string {
	if cesData, ok := c.cesData[name]; ok {
		return cesData.ns
	}
	return ""
}

// Return CES to which the given CEP is assigned
func (c *CESCache) getCESName(cepName CEPName) (CESName, bool) {
	if cepData, ok := c.cepData[cepName]; ok {
		return cepData.ces, true
	}
	return "", false
}

// Return all CESs in the given namespace
func (c *CESCache) getCESInNs(ns string) []CESKey {
	if cesSet, ok := c.nsData[ns]; ok {
		seq := func(yield func(CESKey) bool) {
			for cesName := range cesSet {
				if !yield(NewCESKey(cesName.string(), ns)) {
					return
				}
			}
		}
		return slices.Collect(seq)
	}
	return nil
}

// Return the CID associated with the given CEP. If there are multiple CIDs, return the selected one
// to minimize churn in CES reconciliation.
func (c *CESCache) getCIDForCEP(cepName CEPName) (CID, bool) {
	if cepData, ok := c.cepData[cepName]; ok {
		if secId, ok := c.globalIdLabelsToCIDSet[cepData.labels]; ok {
			return secId.selectedID, true
		}
	}
	return "", false
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

func GetCEPNameFromPod(pod *slim_corev1.Pod) CEPName {
	return NewCEPName(pod.Name, pod.Namespace)
}
