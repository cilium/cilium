// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"k8s.io/apimachinery/pkg/util/sets"

	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
)

type CEPName resource.Key
type CESKey resource.Key
type CESName string
type NodeName string
type EncryptionKey int
type CID string

// CESData contains all CES data, including endpoints.
// CES is reconciled to have endpoints equal to CEPs mapped to it
// and other fields set from the CESData.
type CESData struct {
	ceps sets.Set[CEPName]
	ns   string
}

// SecIDs contains the selected CID, a set of CIDs and a set of CEPs.
// One CID from a set is selected to maintain compatibility with duplicate
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
	labels string
}

// CESCache is used to map Pods/CoreCEPs to CiliumEndpointSlices and
// retrieving all the Pods/CoreCEPs mapped to the given CiliumEndpointSlice.
// This map is protected by a lock for consistent and concurrent access.
type CESCache struct {
	mutex lock.RWMutex

	// cepNameToData is used to map CiliumEndpoint name to the CiliumEndpointSlice, Node and
	// Labels associated with it.
	cepNameToData map[CEPName]*CEPData
	// cesNameToData is used to map CiliumEndpointSlice name to all CiliumEndpoints names it contains
	// and the namespace associated with it
	cesNameToData map[CESName]*CESData
	nsToCESSet    map[string]sets.Set[CESName]
	// nodeNameToData is used to map node name to all CiliumEndpoints on the node
	// and the known encryption key associated with it
	nodeNameToData map[NodeName]*NodeData
	// globalIdLabelsToCIDSet maps a set of labels to the CEPs and CIDs associated with it.
	// Compatible with Agent's CID management which can cause duplicate CIDs.
	globalIdLabelsToCIDSet map[string]*SecIDs
	cidToGidLabels         map[CID]string
}

// Creates and intializes the new CESCache
func newCESCache() *CESCache {
	return &CESCache{
		cepNameToData:          make(map[CEPName]*CEPData),
		cesNameToData:          make(map[CESName]*CESData),
		nodeNameToData:         make(map[NodeName]*NodeData),
		globalIdLabelsToCIDSet: make(map[string]*SecIDs),
		nsToCESSet:             make(map[string]sets.Set[CESName]),
		cidToGidLabels:         make(map[CID]string),
	}
}

// Add CEP to cache, map to CES name and node name
func (c *CESCache) addCEP(cepName CEPName, cesName CESName, nodeName NodeName, gidLabels string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.updateCEPInCache(cepName, nodeName, gidLabels, cesName)
}

// Add or update CEP in cache, map to CES name, node name and associated CID
func (c *CESCache) insertCEP(cepName CEPName, cesName CESName, nodeName NodeName, gidLabels string, cid CID) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.updateCEPInCache(cepName, nodeName, gidLabels, cesName)
	if c.globalIdLabelsToCIDSet[gidLabels].selectedID == "" {
		c.globalIdLabelsToCIDSet[gidLabels].selectedID = cid
	}
	c.globalIdLabelsToCIDSet[gidLabels].ids.Insert(cid)
	c.cidToGidLabels[cid] = gidLabels
}

// Updates known information about CEP in local cache, without CID information. Cache lock should be held by caller.
// Handles the cases where the CEP node or labels may have changed.
func (c *CESCache) updateCEPInCache(cepName CEPName, nodeName NodeName, gidLabels string, cesName CESName) {
	if cepData, ok := c.cepNameToData[cepName]; ok {
		// If CEP was previously mapped to different CES, clear.
		if oldCES := cepData.ces; oldCES != cesName {
			c.cesNameToData[oldCES].ceps.Delete(cepName)
		}

		// If CEP was previously mapped to different node, clear.
		if oldNode := cepData.node; oldNode != nodeName {
			c.nodeNameToData[oldNode].ceps.Delete(cepName)
		}
		// If CEP was previously mapped to different labels, clear.
		if oldLabels := cepData.labels; oldLabels != gidLabels {
			c.globalIdLabelsToCIDSet[gidLabels].ceps.Delete(cepName)
			c.cleanLabelsMap(oldLabels)
		}
	}

	c.cepNameToData[cepName] = &CEPData{
		ces:    cesName,
		node:   nodeName,
		labels: gidLabels,
	}

	c.cesNameToData[cesName].ceps.Insert(cepName)

	if _, ok := c.nodeNameToData[nodeName]; !ok {
		c.nodeNameToData[nodeName] = &NodeData{
			ceps: sets.New[CEPName](),
		}
	}
	c.nodeNameToData[nodeName].ceps.Insert(cepName)

	if _, ok := c.globalIdLabelsToCIDSet[gidLabels]; !ok {
		c.globalIdLabelsToCIDSet[gidLabels] = &SecIDs{
			ids:  sets.New[CID](),
			ceps: sets.New[CEPName](),
		}
	}
	c.globalIdLabelsToCIDSet[gidLabels].ceps.Insert(cepName)
}

// Update encryption key for node and return all affected CES whose CEPs are on that node.
func (c *CESCache) insertNode(nodeName NodeName, encryptionKey EncryptionKey) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, ok := c.nodeNameToData[nodeName]; !ok {
		c.nodeNameToData[nodeName] = &NodeData{
			ceps: sets.New[CEPName](),
			key:  encryptionKey,
		}
		return nil
	}

	if c.nodeNameToData[nodeName].key != encryptionKey {
		c.nodeNameToData[nodeName].key = encryptionKey
		return c.getCESForCEPs(c.nodeNameToData[nodeName].ceps)
	}
	return nil
}

// Insert a CID into the cache and return the CES which need to be reconciled
func (c *CESCache) insertCID(cid CID, gidLabels string) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clean up old state
	if oldLabels, ok := c.cidToGidLabels[cid]; ok && oldLabels != gidLabels {
		c.globalIdLabelsToCIDSet[oldLabels].ids.Delete(cid)
		// If the selectedID is the same as the CID being removed, update it to another valid CID, if it exists.
		if c.globalIdLabelsToCIDSet[oldLabels].selectedID == cid {
			c.globalIdLabelsToCIDSet[oldLabels].selectedID = ""
			for nextID := range c.globalIdLabelsToCIDSet[oldLabels].ids {
				c.globalIdLabelsToCIDSet[oldLabels].selectedID = nextID
				break
			}
		}
		c.cleanLabelsMap(oldLabels)
		delete(c.cidToGidLabels, cid)
	}

	if _, ok := c.globalIdLabelsToCIDSet[gidLabels]; !ok {
		c.globalIdLabelsToCIDSet[gidLabels] = &SecIDs{
			ids:  sets.New[CID](),
			ceps: sets.New[CEPName](),
		}
	}
	if c.globalIdLabelsToCIDSet[gidLabels].selectedID == "" {
		c.globalIdLabelsToCIDSet[gidLabels].selectedID = cid
	}
	c.globalIdLabelsToCIDSet[gidLabels].ids.Insert(cid)
	return c.getCESForCEPs(c.globalIdLabelsToCIDSet[gidLabels].ceps)
}

// Remove the CEP entry from map
func (c *CESCache) deleteCEP(cepName CEPName) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if cepData, ok := c.cepNameToData[cepName]; ok {
		if _, ok := c.nodeNameToData[cepData.node]; ok {
			c.nodeNameToData[cepData.node].ceps.Delete(cepName)
		}

		if _, ok := c.globalIdLabelsToCIDSet[cepData.labels]; ok {
			c.globalIdLabelsToCIDSet[cepData.labels].ceps.Delete(cepName)
			c.cleanLabelsMap(cepData.labels)
		}

		c.cesNameToData[cepData.ces].ceps.Delete(cepName)
	}
	delete(c.cepNameToData, cepName)
}

// Remove node from cache and return affected CES
func (c *CESCache) deleteNode(nodeName NodeName) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if nodeData, ok := c.nodeNameToData[nodeName]; ok {
		cesKeys := c.getCESForCEPs(nodeData.ceps)
		delete(c.nodeNameToData, nodeName)
		return cesKeys
	}
	return nil
}

// Remove CID from cache and return affected CES
func (c *CESCache) deleteCID(cid CID, gidLabels string) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.cidToGidLabels, cid)
	if secId, ok := c.globalIdLabelsToCIDSet[gidLabels]; ok {
		if secId.ids.Has(cid) {
			cesKeys := c.getCESForCEPs(secId.ceps)
			secId.ids.Delete(cid)
			if secId.selectedID == cid {
				// If the selectedID is the same as the CID being removed, update it to another valid CID, if it exists.
				c.globalIdLabelsToCIDSet[gidLabels].selectedID = ""
				for nextID := range secId.ids {
					c.globalIdLabelsToCIDSet[gidLabels].selectedID = nextID
					break
				}
			}
			c.cleanLabelsMap(gidLabels)
			return cesKeys
		}
	}
	return nil
}

// Clean up globalIdLabelsToCIDSet map, if no label state exists.
// Caller should hold cache lock.
func (c *CESCache) cleanLabelsMap(gidLabels string) {
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
	if cepData, ok := c.cepNameToData[cepName]; ok {
		return cepData.ces, true
	}
	return "", false
}

func (c *CESCache) hasCEP(cepName CEPName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cepNameToData[cepName]
	return ok
}

func (c *CESCache) hasNode(nodeName NodeName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.nodeNameToData[nodeName]
	return ok
}

func (c *CESCache) hasCID(cid CID, gidLabels string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	_, ok := c.cidToGidLabels[cid]
	return ok
}

// Return total number of CEPs stored in cache
func (c *CESCache) countCEPs() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cepNameToData)
}

// Return total number of CEPs mapped to the given CES
func (c *CESCache) countCEPsInCES(ces CESName) int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if cesData, ok := c.cesNameToData[ces]; ok {
		return cesData.ceps.Len()
	}
	return 0
}

// Return CEP Names mapped to the given CES
func (c *CESCache) getCEPsInCES(ces CESName) []CEPName {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.cesNameToData[ces].ceps.UnsortedList()
}

// Initializes mapping structure for CES
func (c *CESCache) insertCES(cesName CESName, ns string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cesNameToData[cesName] = &CESData{
		ceps: sets.New[CEPName](),
		ns:   ns,
	}
	if _, ok := c.nsToCESSet[ns]; !ok {
		c.nsToCESSet[ns] = sets.New[CESName]()
	}
	c.nsToCESSet[ns].Insert(cesName)
}

// Remove mapping structure for CES
func (c *CESCache) deleteCES(cesName CESName) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.cesNameToData, cesName)
	if cesns, ok := c.cesNameToData[cesName]; ok {
		c.nsToCESSet[cesns.ns].Delete(cesName)
	}
}

func (c *CESCache) hasCESName(cesName CESName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cesNameToData[cesName]
	return ok
}

// Return the total number of CESs.
func (c *CESCache) getCESCount() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cesNameToData)
}

// Return names of all CESs.
func (c *CESCache) getAllCESs() []CESName {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	cess := make([]CESName, 0, len(c.cesNameToData))
	for ces := range c.cesNameToData {
		cess = append(cess, ces)
	}
	return cess
}

// Return the namespace of the given CES
func (c *CESCache) getCESNamespace(name CESName) string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if cesData, ok := c.cesNameToData[name]; ok {
		return cesData.ns
	}
	return ""
}

func (c *CESCache) getCESInNs(ns string) []CESKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if _, ok := c.nsToCESSet[ns]; !ok {
		return nil
	}
	cess := make([]CESKey, 0, c.nsToCESSet[ns].Len())
	for ces := range c.nsToCESSet[ns] {
		if cesData, ok := c.cesNameToData[ces]; ok {
			cess = append(cess, NewCESKey(ces.string(), cesData.ns))
		}
	}
	return cess
}

func (c *CESCache) deleteNs(ns string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.nsToCESSet, ns)
}

func (c *CESCache) getCESForCEPs(ceps sets.Set[CEPName]) []CESKey {
	cesKeys := make([]CESKey, 0, ceps.Len())
	for cepName := range ceps {
		if cepData, ok := c.cepNameToData[cepName]; ok {
			cesName := cepData.ces
			cesKeys = append(cesKeys, NewCESKey(cesName.string(), c.cesNameToData[cesName].ns))
		}
	}
	return cesKeys
}

func (c *CESCache) getCIDForCEP(cepName CEPName) (CID, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if cepData, ok := c.cepNameToData[cepName]; ok {
		if secId, ok := c.globalIdLabelsToCIDSet[cepData.labels]; ok {
			return secId.selectedID, true
		}
	}
	return "", false
}

func (ces CESKey) key() resource.Key {
	return resource.Key(ces)
}

func (cep CEPName) key() resource.Key {
	return resource.Key(cep)
}

func (ces CESKey) string() string {
	return ces.key().String()
}

func (cep CEPName) string() string {
	return cep.key().String()
}

func (c CESName) string() string {
	return string(c)
}

func (cid CID) string() string {
	return string(cid)
}

// NewCESKey is used with namespace only to determine which queue CES should be in.
// CES is a cluster-scope object and it does not contain the metadata namespace field.
func NewCESKey(name string, namespace string) CESKey {
	return CESKey(resource.Key{Name: name, Namespace: namespace})
}

func NewCEPName(name, ns string) CEPName {
	return CEPName(resource.Key{Name: name, Namespace: ns})
}

func GetCEPNameFromCCEP(cep *capi_v2a1.CoreCiliumEndpoint, namespace string) CEPName {
	return NewCEPName(cep.Name, namespace)
}

func GetCEPNameFromPod(pod *slim_corev1.Pod) CEPName {
	return NewCEPName(pod.Name, pod.Namespace)
}
