// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"cmp"

	"github.com/cilium/cilium/pkg/lock"
	"k8s.io/apimachinery/pkg/util/sets"
)

type NodeName string
type EncryptionKey int
type CID string
type Label string

type CESCacher interface {
	hasCESName(cesName CESName) bool
	insertCES(cesName CESName, ns string)
}

// NodeData contains information about the node; the set of coreceps on
// the node and the known encryption key associated with the node.
type NodeData struct {
	ceps sets.Set[CEPName]
	key  EncryptionKey
}

func NewNodeData() *NodeData {
	return &NodeData{
		ceps: sets.New[CEPName](),
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

type CESCache struct {
	mutex lock.RWMutex

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
		cesData:                make(map[CESName]*CESData),
		nsData:                 make(map[string]sets.Set[CESName]),
		nodeData:               make(map[NodeName]*NodeData),
		globalIdLabelsToCIDSet: make(map[Label]*SecIDs),
		cidToGidLabels:         make(map[CID]Label),
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

// Remove node from cache and return affected CESs
func (c *CESCache) deleteNode(nodeName NodeName) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if nodeData, ok := c.nodeData[nodeName]; ok {
		// TODO: Clean up node state in CEPData
		cesKeys := c.getCESForCEPs(nodeData.ceps)
		delete(c.nodeData, nodeName)
		return cesKeys
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

// Return if given node is present in cache
func (c *CESCache) hasNode(nodeName NodeName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.nodeData[nodeName]
	return ok
}

// Return CES keys for the given CEPs. Caller must hold the cache lock.
func (c *CESCache) getCESForCEPs(ceps sets.Set[CEPName]) []CESKey {
	// TODO: Implement when CEP/CES state is tracked in cache
	return nil
}

// Return if given CID is present in cache
func (c *CESCache) hasCID(cid CID, gidLabels Label) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cidToGidLabels[cid]
	return ok
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

// Clean up globalIdLabelsToCIDSet map, if no label state exists.
// Caller should hold cache lock.
func (c *CESCache) cleanLabelsMap(gidLabels Label) {
	if secId, ok := c.globalIdLabelsToCIDSet[gidLabels]; ok {
		if secId.ceps.Len() == 0 && secId.ids.Len() == 0 {
			delete(c.globalIdLabelsToCIDSet, gidLabels)
		}
	}
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

func (cid CID) String() string {
	return string(cid)
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
