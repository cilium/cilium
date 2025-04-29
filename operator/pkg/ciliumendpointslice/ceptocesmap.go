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

// To maintain compatibility with duplicate CIDs.
type SecIDs struct {
	ids  sets.Set[CID]
	ceps sets.Set[CEPName]
}

type NodeData struct {
	ceps sets.Set[CEPName]
	key  EncryptionKey
}

// CESToCEPMapping is used to map Cilium Endpoints to CiliumEndpointSlices and
// retrieving all the Cilium Endpoints mapped to the given CiliumEndpointSlice.
// This map is protected by lock for consistent and concurrent access.
type CESToCEPMapping struct {
	mutex lock.RWMutex

	// cepNameToCESName is used to map CiliumEndpoint name to CiliumEndpointSlice name.
	cepNameToCESName map[CEPName]CESName
	// cesNameToCEPNameSet is used to map CiliumEndpointSlice name to all CiliumEndpoints names it contains.
	cesNameToCEPNameSet map[CESName]sets.Set[CEPName]
	cesData             map[CESName]CESData

	// nodeNameToNodeData is used to map node name to all CiliumEndpoints on the node
	// and the known encryption key associated with it
	nodeNameToNodeData map[NodeName]*NodeData
	cepNameToNodeName  map[CEPName]NodeName

	// globalIdLabelsToCIDSet maps a set of labels to the CEPs and CIDs associated with it.
	// Compatible with Agent's CID management which can cause duplicate CIDs.
	globalIdLabelsToCIDSet  map[string]*SecIDs
	cepNameToGlobalIdLabels map[CEPName]string

	nsToCESSet map[string]sets.Set[CESName]
}

// CESData contains all CES data except endpoints.
// CES is reconicled to have endpoints equal to CEPs mapped to it
// and other fields set from the CESData.
type CESData struct {
	ns string
}

// Creates and intializes the new CESToCEPMapping
func newCESToCEPMapping() *CESToCEPMapping {
	return &CESToCEPMapping{
		cepNameToCESName:        make(map[CEPName]CESName),
		cesNameToCEPNameSet:     make(map[CESName]sets.Set[CEPName]),
		cesData:                 make(map[CESName]CESData),
		nodeNameToNodeData:      make(map[NodeName]*NodeData),
		cepNameToNodeName:       make(map[CEPName]NodeName),
		globalIdLabelsToCIDSet:  make(map[string]*SecIDs),
		cepNameToGlobalIdLabels: make(map[CEPName]string),
		nsToCESSet:              make(map[string]sets.Set[CESName]),
	}
}

// Add CEP to cache, map to CES name and node name
func (c *CESToCEPMapping) addCEP(cepName CEPName, cesName CESName, nodeName NodeName, gidLabels string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.updateCEPInCache(cepName, nodeName, gidLabels, cesName)
}

// Insert the CEP in cache, map to CES name, node name and associated CID
func (c *CESToCEPMapping) insertCEP(cepName CEPName, cesName CESName, nodeName NodeName, gidLabels string, cid CID) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.updateCEPInCache(cepName, nodeName, gidLabels, cesName)
	c.globalIdLabelsToCIDSet[gidLabels].ids.Insert(cid)
}

// Updates known information about CEP in local cache, without CID information. Cache lock should be held by caller.
// Handles the cases where the CEP node or labels may have changed.
func (c *CESToCEPMapping) updateCEPInCache(cepName CEPName, nodeName NodeName, gidLabels string, cesName CESName) {
	c.cepNameToCESName[cepName] = cesName
	c.cesNameToCEPNameSet[cesName].Insert(cepName)

	// If CEP was previously mapped to different node, clear.
	if oldNode, ok := c.cepNameToNodeName[cepName]; ok && oldNode != nodeName {
		c.nodeNameToNodeData[oldNode].ceps.Delete(cepName)
	}
	// If CEP was previously mapped to different labels, clear.
	if oldLabels, ok := c.cepNameToGlobalIdLabels[cepName]; ok && oldLabels != gidLabels {
		delete(c.cepNameToGlobalIdLabels, cepName)
		c.globalIdLabelsToCIDSet[gidLabels].ceps.Delete(cepName)
	}

	if _, ok := c.nodeNameToNodeData[nodeName]; !ok {
		c.nodeNameToNodeData[nodeName] = &NodeData{
			ceps: make(sets.Set[CEPName]),
		}
	}
	c.nodeNameToNodeData[nodeName].ceps.Insert(cepName)
	c.cepNameToNodeName[cepName] = nodeName

	if _, ok := c.globalIdLabelsToCIDSet[gidLabels]; !ok {
		c.globalIdLabelsToCIDSet[gidLabels] = &SecIDs{
			ids:  make(sets.Set[CID]),
			ceps: make(sets.Set[CEPName]),
		}
	}
	c.globalIdLabelsToCIDSet[gidLabels].ceps.Insert(cepName)
	c.cepNameToGlobalIdLabels[cepName] = gidLabels
}

// Update encryption key for node and return all affected CES whose CEPs are on that node.
func (c *CESToCEPMapping) insertNode(nodeName NodeName, encryptionKey EncryptionKey) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, ok := c.nodeNameToNodeData[nodeName]; !ok {
		c.nodeNameToNodeData[nodeName] = &NodeData{
			ceps: make(sets.Set[CEPName]),
			key:  encryptionKey,
		}
		return nil
	}

	c.nodeNameToNodeData[nodeName].key = encryptionKey
	cesKeys := make([]CESKey, 0, c.nodeNameToNodeData[nodeName].ceps.Len())
	for cepName := range c.nodeNameToNodeData[nodeName].ceps {
		cesName := c.cepNameToCESName[cepName]
		cesKeys = append(cesKeys, NewCESKey(cesName.string(), c.cesData[cesName].ns))
	}
	return cesKeys
}

// Insert a CID into the cache and return the CES which need to be reconciled
func (c *CESToCEPMapping) insertCID(cid CID, gidLabels string) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, ok := c.globalIdLabelsToCIDSet[gidLabels]; !ok {
		c.globalIdLabelsToCIDSet[gidLabels] = &SecIDs{
			ids:  make(sets.Set[CID]),
			ceps: make(sets.Set[CEPName]),
		}
	}
	c.globalIdLabelsToCIDSet[gidLabels].ids.Insert(cid)

	cesKeys := make([]CESKey, 0, c.globalIdLabelsToCIDSet[gidLabels].ceps.Len())
	for cepName := range c.globalIdLabelsToCIDSet[gidLabels].ceps {
		cesName := c.cepNameToCESName[cepName]
		cesKeys = append(cesKeys, NewCESKey(cesName.string(), c.cesData[cesName].ns))
	}
	return cesKeys
}

// Remove the CEP entry from map
func (c *CESToCEPMapping) deleteCEP(cepName CEPName) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if node, ok := c.cepNameToNodeName[cepName]; ok {
		if _, ok := c.nodeNameToNodeData[node]; ok {
			c.nodeNameToNodeData[node].ceps.Delete(cepName)
		}
	}
	delete(c.cepNameToNodeName, cepName)

	if labels, ok := c.cepNameToGlobalIdLabels[cepName]; ok {
		if _, ok := c.globalIdLabelsToCIDSet[labels]; ok {
			c.globalIdLabelsToCIDSet[labels].ceps.Delete(cepName)
			c.cleanLabelsMap(labels)
		}
	}
	delete(c.cepNameToGlobalIdLabels, cepName)

	c.cesNameToCEPNameSet[c.cepNameToCESName[cepName]].Delete(cepName)
	delete(c.cepNameToCESName, cepName)
}

// Remove node from cache and return affected CES
func (c *CESToCEPMapping) deleteNode(nodeName NodeName) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	cesKeys := make([]CESKey, 0, c.nodeNameToNodeData[nodeName].ceps.Len())
	for cepName := range c.nodeNameToNodeData[nodeName].ceps {
		cesName := c.cepNameToCESName[cepName]
		cesKeys = append(cesKeys, NewCESKey(cesName.string(), c.cesData[cesName].ns))
	}
	delete(c.nodeNameToNodeData, nodeName)
	return cesKeys
}

// Remove CID from cache and return affected CES
func (c *CESToCEPMapping) deleteCID(cid CID, gidLabels string) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if secId, ok := c.globalIdLabelsToCIDSet[gidLabels]; ok {
		if secId.ids.Has(cid) {
			cesKeys := make([]CESKey, 0, secId.ceps.Len())
			for cepName := range secId.ceps {
				cesName := c.cepNameToCESName[cepName]
				cesKeys = append(cesKeys, NewCESKey(cesName.string(), c.cesData[cesName].ns))
			}
			secId.ids.Delete(cid)
			c.cleanLabelsMap(gidLabels)

			return cesKeys
		}
	}
	return nil
}

// Clean up globalIdLabelsToCIDSet map, if no label state exists.
// Caller should hold cache lock.
func (c *CESToCEPMapping) cleanLabelsMap(gidLabels string) {
	if secId, ok := c.globalIdLabelsToCIDSet[gidLabels]; ok {
		if secId.ceps.Len() == 0 && secId.ids.Len() == 0 {
			delete(c.globalIdLabelsToCIDSet, gidLabels)
		}
	}
}

// Return CES to which the given CEP is assigned
func (c *CESToCEPMapping) getCESName(cepName CEPName) (CESName, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	name, ok := c.cepNameToCESName[cepName]
	return name, ok
}

func (c *CESToCEPMapping) hasCEP(cepName CEPName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cepNameToCESName[cepName]
	return ok
}

func (c *CESToCEPMapping) hasNode(nodeName NodeName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.nodeNameToNodeData[nodeName]
	return ok
}

func (c *CESToCEPMapping) hasCID(cid CID, gidLabels string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if _, ok := c.globalIdLabelsToCIDSet[gidLabels]; !ok {
		return false
	}
	for id := range c.globalIdLabelsToCIDSet[gidLabels].ids {
		if id == cid {
			return true
		}
	}
	return false
}

// Return total number of CEPs stored in cache
func (c *CESToCEPMapping) countCEPs() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cepNameToCESName)
}

// Return total number of CEPs mapped to the given CES
func (c *CESToCEPMapping) countCEPsInCES(ces CESName) int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.cesNameToCEPNameSet[ces].Len()
}

// Return CEP Names mapped to the given CES
func (c *CESToCEPMapping) getCEPsInCES(ces CESName) []CEPName {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	ceps := make([]CEPName, 0, c.cesNameToCEPNameSet[ces].Len())
	for cep := range c.cesNameToCEPNameSet[ces] {
		ceps = append(ceps, cep)
	}
	return ceps
}

func (c *CESToCEPMapping) getNodeEncryptionKey(nodeName NodeName) EncryptionKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.nodeNameToNodeData[nodeName].key
}

// Initializes mapping structure for CES
func (c *CESToCEPMapping) insertCES(cesName CESName, ns string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cesNameToCEPNameSet[cesName] = make(sets.Set[CEPName])
	c.cesData[cesName] = CESData{
		ns: ns,
	}
	if _, ok := c.nsToCESSet[ns]; !ok {
		c.nsToCESSet[ns] = make(sets.Set[CESName])
	}
	c.nsToCESSet[ns].Insert(cesName)
}

// Remove mapping structure for CES
func (c *CESToCEPMapping) deleteCES(cesName CESName) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.cesNameToCEPNameSet, cesName)
	if cesns, ok := c.cesData[cesName]; ok {
		c.nsToCESSet[cesns.ns].Delete(cesName)
	}
	delete(c.cesData, cesName)
}

func (c *CESToCEPMapping) hasCESName(cesName CESName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cesNameToCEPNameSet[cesName]
	return ok
}

// Return the total number of CESs.
func (c *CESToCEPMapping) getCESCount() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cesNameToCEPNameSet)
}

// Return names of all CESs.
func (c *CESToCEPMapping) getAllCESs() []CESName {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	cess := make([]CESName, 0, len(c.cesNameToCEPNameSet))
	for ces := range c.cesNameToCEPNameSet {
		cess = append(cess, ces)
	}
	return cess
}

// Return the CES data
func (c *CESToCEPMapping) getCESData(name CESName) CESData {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	data := c.cesData[name]
	return data
}

func (c *CESToCEPMapping) getCESInNs(ns string) []CESKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	cess := make([]CESKey, 0, c.nsToCESSet[ns].Len())
	for ces := range c.nsToCESSet[ns] {
		cess = append(cess, NewCESKey(ces.string(), c.cesData[ces].ns))
	}
	return cess
}

func (c *CESToCEPMapping) deleteNs(ns string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.nsToCESSet, ns)
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
