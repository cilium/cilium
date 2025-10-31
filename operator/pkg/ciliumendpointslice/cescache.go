// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"cmp"

	"k8s.io/apimachinery/pkg/util/sets"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
)

type NodeName string
type EncryptionKey int
type CID string
type Label string

// SecIDs contains the selected CID, a set of CIDs and a set of CEPs.
// One CID from the set is selected to maintain compatibility with duplicate
// identities.
type SecIDs struct {
	selectedID CID
	ids        sets.Set[CID]
	ceps       sets.Set[CEPName]
}

// NodeData contains information about the node; the set of coreceps on
// the node and the known encryption key associated with the node.
type NodeData struct {
	ceps sets.Set[CEPName]
	key  EncryptionKey
}

// CEPData contains the CES, node and labels associated with the corecep.
type CEPData struct {
	ces    CESName
	node   NodeName
	labels Label
}

// CESCache is used to map Pods/CoreCEPs to CiliumEndpointSlices and
// retrieving all the Pods/CoreCEPs mapped to the given CiliumEndpointSlice.
// This map is protected by a lock for consistent and concurrent access.
type CESCache struct {
	mutex lock.RWMutex

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
	globalIdLabelsToCIDSet map[Label]*SecIDs
	// cidToGidLabels maps CID to the GID labels associated with it.
	cidToGidLabels map[CID]Label
}

// Creates and intializes the new CESCache
func newCESCache() *CESCache {
	return &CESCache{
		cepData:                make(map[CEPName]*CEPData),
		cesData:                make(map[CESName]*CESData),
		nsData:                 make(map[string]sets.Set[CESName]),
		nodeData:               make(map[NodeName]*NodeData),
		globalIdLabelsToCIDSet: make(map[Label]*SecIDs),
		cidToGidLabels:         make(map[CID]Label),
	}
}

// Initializes CESData with given namespace
func NewCESData(ns string) *CESData {
	return &CESData{
		ceps: sets.New[CEPName](),
		ns:   ns,
	}
}

func NewSecIDs() *SecIDs {
	return &SecIDs{
		ids:  sets.New[CID](),
		ceps: sets.New[CEPName](),
	}
}

func NewNodeData() *NodeData {
	return &NodeData{
		ceps: sets.New[CEPName](),
	}
}

// Add CEP to cache, map to CES name and node name
func (c *CESCache) addCEP(cepName CEPName, cesName CESName, nodeName NodeName, gidLabels Label) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.updateCEPInCache(cepName, nodeName, gidLabels, cesName)
}

// Add or update CEP in cache, map to CES name, node name and associated CID
func (c *CESCache) upsertCEP(cepName CEPName, cesName CESName, nodeName NodeName, gidLabels Label, cid CID) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.updateCEPInCache(cepName, nodeName, gidLabels, cesName)
	c.globalIdLabelsToCIDSet[gidLabels].setSelectedID(cid, false)
	c.globalIdLabelsToCIDSet[gidLabels].ids.Insert(cid)
	c.cidToGidLabels[cid] = gidLabels
}

// Updates known information about CEP in local cache, without CID information. Cache lock should be held by caller.
// Handles the cases where the CEP node or labels may have changed.
func (c *CESCache) updateCEPInCache(cepName CEPName, nodeName NodeName, gidLabels Label, cesName CESName) {
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
// Cache lock should be held by caller.
func (c *CESCache) clearStaleState(cepName CEPName, newNodeName NodeName, newGIDLabels Label, newCESName CESName) {
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
			c.cleanLabelsMap(oldLabels)
		}
	}
}

// Update encryption key for node and return all affected CES whose CEPs are on that node.
func (c *CESCache) insertNode(nodeName NodeName, encryptionKey EncryptionKey) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, ok := c.nodeData[nodeName]; !ok {
		c.nodeData[nodeName] = NewNodeData()
		c.nodeData[nodeName].key = encryptionKey
		return nil
	}

	if c.nodeData[nodeName].key != encryptionKey {
		c.nodeData[nodeName].key = encryptionKey
		return c.getCESForCEPs(c.nodeData[nodeName].ceps)
	}
	return nil
}

// Insert a CID into the cache and return the CESs which need to be reconciled
func (c *CESCache) insertCID(cid CID, gidLabels Label) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clean up old state
	if oldLabels, ok := c.cidToGidLabels[cid]; ok && oldLabels != gidLabels {
		c.globalIdLabelsToCIDSet[oldLabels].ids.Delete(cid)
		// If the selectedID is the same as the CID being removed, update it to another valid CID, if it exists.
		if c.globalIdLabelsToCIDSet[oldLabels].selectedID == cid {
			c.globalIdLabelsToCIDSet[oldLabels].setSelectedID("", true)
		}
		c.cleanLabelsMap(oldLabels)
	}
	c.cidToGidLabels[cid] = gidLabels

	if _, ok := c.globalIdLabelsToCIDSet[gidLabels]; !ok {
		c.globalIdLabelsToCIDSet[gidLabels] = NewSecIDs()
	}
	c.globalIdLabelsToCIDSet[gidLabels].setSelectedID(cid, false)
	c.globalIdLabelsToCIDSet[gidLabels].ids.Insert(cid)
	return c.getCESForCEPs(c.globalIdLabelsToCIDSet[gidLabels].ceps)
}

// Remove the CEP entry from mappings
func (c *CESCache) deleteCEP(cepName CEPName) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if cepData, ok := c.cepData[cepName]; ok {
		if _, ok := c.nodeData[cepData.node]; ok {
			c.nodeData[cepData.node].ceps.Delete(cepName)
		}

		if _, ok := c.globalIdLabelsToCIDSet[cepData.labels]; ok {
			c.globalIdLabelsToCIDSet[cepData.labels].ceps.Delete(cepName)
			c.cleanLabelsMap(cepData.labels)
		}

		c.cesData[cepData.ces].ceps.Delete(cepName)
	}
	delete(c.cepData, cepName)
}

// Remove node from cache and return affected CESs
func (c *CESCache) deleteNode(nodeName NodeName) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if nodeData, ok := c.nodeData[nodeName]; ok {
		for cepName := range nodeData.ceps {
			c.cepData[cepName].node = ""
		}
		cesKeys := c.getCESForCEPs(nodeData.ceps)
		delete(c.nodeData, nodeName)
		return cesKeys
	}
	return nil
}

// Remove CID from cache and return affected CESs
func (c *CESCache) deleteCID(cid CID, gidLabels Label) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.cidToGidLabels, cid)
	if secId, ok := c.globalIdLabelsToCIDSet[gidLabels]; ok {
		if secId.ids.Has(cid) {
			cesKeys := c.getCESForCEPs(secId.ceps)
			secId.ids.Delete(cid)
			if secId.selectedID == cid {
				// If the selectedID is the same as the CID being removed, update it to another valid CID, if it exists.
				secId.setSelectedID("", true)
			}
			c.cleanLabelsMap(gidLabels)
			return cesKeys
		}
	}
	return nil
}

// SetSelectedID will update the selectedID to the given CID if not set.
// If findNextCID is true, it will find the next available CID
// and update selectedID to it, or set to empty if no CIDs are available.
// Caller should hold cache lock.
func (s *SecIDs) setSelectedID(newCID CID, findNextCID bool) {
	if findNextCID {
		for nextID := range s.ids {
			s.selectedID = nextID
			return
		}
	}
	s.selectedID = cmp.Or(s.selectedID, newCID)
}

// Clean up globalIdLabelsToCIDSet map, if no label state exists.
// Caller should hold cache lock.
func (c *CESCache) cleanLabelsMap(gidLabels Label) {
	if secId, ok := c.globalIdLabelsToCIDSet[gidLabels]; ok {
		if secId.ceps.Len() == 0 && secId.ids.Len() == 0 {
			delete(c.globalIdLabelsToCIDSet, gidLabels)
		}
	}
}

// Return CES to which the given CEP is assigned
func (c *CESCache) getCESName(cepName CEPName) (CESName, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if cepData, ok := c.cepData[cepName]; ok {
		return cepData.ces, true
	}
	return "", false
}

// Return if the given CEP is present in cache
func (c *CESCache) hasCEP(cepName CEPName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cepData[cepName]
	return ok
}

// Return if given node is present in cache
func (c *CESCache) hasNode(nodeName NodeName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.nodeData[nodeName]
	return ok
}

// Return if given CID is present in cache
func (c *CESCache) hasCID(cid CID, gidLabels Label) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cidToGidLabels[cid]
	return ok
}

// Return total number of CEPs stored in cache
func (c *CESCache) countCEPs() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cepData)
}

// Return total number of CEPs mapped to the given CES
func (c *CESCache) countCEPsInCES(ces CESName) int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if cesData, ok := c.cesData[ces]; ok {
		return cesData.ceps.Len()
	}
	return 0
}

// Return CEP Names mapped to the given CES
func (c *CESCache) getCEPsInCES(ces CESName) []CEPName {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if cesData, ok := c.cesData[ces]; ok {
		return cesData.ceps.UnsortedList()
	}
	return nil
}

// Initializes mapping structure for CES
func (c *CESCache) insertCES(cesName CESName, ns string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cesData[cesName] = NewCESData(ns)
	if _, ok := c.nsData[ns]; !ok {
		c.nsData[ns] = sets.New[CESName]()
	}
	c.nsData[ns].Insert(cesName)
}

// Remove mapping structure for CES
func (c *CESCache) deleteCES(cesName CESName) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if cesData, ok := c.cesData[cesName]; ok {
		if cesSet, ok := c.nsData[cesData.ns]; ok {
			cesSet.Delete(cesName)
		}
	}
	delete(c.cesData, cesName)
}

// Return if the given CES is present in cache
func (c *CESCache) hasCESName(cesName CESName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cesData[cesName]
	return ok
}

// Return the total number of CESs.
func (c *CESCache) getCESCount() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cesData)
}

// Return names of all CESs.
func (c *CESCache) getAllCESs() []CESName {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	cess := make([]CESName, 0, len(c.cesData))
	for ces := range c.cesData {
		cess = append(cess, ces)
	}
	return cess
}

// Return the namespace of the given CES
func (c *CESCache) getCESNamespace(name CESName) string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if cesData, ok := c.cesData[name]; ok {
		return cesData.ns
	}
	return ""
}

// Return all CESs in the given namespace
func (c *CESCache) getCESInNs(ns string) []CESKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if cesSet, ok := c.nsData[ns]; ok {
		cess := make([]CESKey, 0, cesSet.Len())
		for ces := range cesSet {
			cess = append(cess, NewCESKey(ces.string(), ns))
		}
		return cess
	}
	return nil
}

// Delete namespace from cache
func (c *CESCache) deleteNs(ns string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for ces := range c.nsData[ns] {
		c.cesData[ces].ns = ""
	}
	delete(c.nsData, ns)
}

// Return CES keys for the given CEPs. Caller must hold the cache lock.
func (c *CESCache) getCESForCEPs(ceps sets.Set[CEPName]) []CESKey {
	cesKeys := make([]CESKey, 0, ceps.Len())
	for cepName := range ceps {
		if cepData, ok := c.cepData[cepName]; ok {
			cesName := cepData.ces
			cesKeys = append(cesKeys, NewCESKey(cesName.string(), c.cesData[cesName].ns))
		}
	}
	return cesKeys
}

// Return the CID associated with the given CEP. If there are multiple CIDs, return the selected one
// to minimize churn in CES reconciliation.
func (c *CESCache) getCIDForCEP(cepName CEPName) (CID, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if cepData, ok := c.cepData[cepName]; ok {
		if secId, ok := c.globalIdLabelsToCIDSet[cepData.labels]; ok {
			return secId.selectedID, true
		}
	}
	return "", false
}

// Return the selected CID for the given GID labels
func (c *CESCache) GetSelectedId(gid Label) (CID, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if gidData, ok := c.globalIdLabelsToCIDSet[gid]; ok {
		return gidData.selectedID, true
	}
	return "", false
}

func (cid CID) string() string {
	return string(cid)
}

func GetCEPNameFromPod(pod *slim_corev1.Pod) CEPName {
	return NewCEPName(pod.Name, pod.Namespace)
}
