// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"fmt"

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
	labels string
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
	nsData  map[string]sets.Set[CESName]
	// nodeData is used to map node name to all CiliumEndpoints on the node
	// and the known encryption key associated with it
	nodeData map[NodeName]*NodeData
	// globalIdLabelsToCIDSet maps a set of labels to the CEPs and CIDs associated with it.
	// Compatible with Agent's CID management which can cause duplicate CIDs.
	globalIdLabelsToCIDSet map[string]*SecIDs
	cidToGidLabels         map[CID]string
}

// Creates and intializes the new CESCache
func newCESCache() *CESCache {
	return &CESCache{
		cepData:                make(map[CEPName]*CEPData),
		cesData:                make(map[CESName]*CESData),
		nsData:                 make(map[string]sets.Set[CESName]),
		nodeData:               make(map[NodeName]*NodeData),
		globalIdLabelsToCIDSet: make(map[string]*SecIDs),
		cidToGidLabels:         make(map[CID]string),
	}
}

func (c *CESCache) DumpState() string {
	s := "===== CESCache =====\n"
	s += "CEP Data\n"
	for cep, data := range c.cepData {
		s += fmt.Sprintf("  %s: { CES: %s, Node: %s, Labels: %s }\n", cep, data.ces, data.node, data.labels)
	}
	s += "CES Data\n"
	for ces, data := range c.cesData {
		s += fmt.Sprintf("  %s: { CEPs: %s, Namespace: %s }\n", ces, data.ceps, data.ns)
	}
	s += "Node Data\n"
	for node, data := range c.nodeData {
		s += fmt.Sprintf("  %s: { CEPs: %s, Key: %d }\n", node, data.ceps, data.key)
	}
	s += "Global ID Labels to CID Set\n"
	for labels, data := range c.globalIdLabelsToCIDSet {
		s += fmt.Sprintf("  %s: { SelectedID: %d, IDs: %s, CEPs: %s }\n", labels, data.selectedID, data.ids, data.ceps)
	}
	s += "CID to Global ID Labels\n"
	for cid, labels := range c.cidToGidLabels {
		s += fmt.Sprintf("  %d: %s\n", cid, labels)
	}
	return s
}

// Add CEP to cache, map to CES name and node name
func (c *CESCache) addCEP(cepName CEPName, cesName CESName, nodeName NodeName, gidLabels string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	fmt.Println("addCEP called:", cepName, cesName, nodeName, gidLabels)
	c.updateCEPInCache(cepName, nodeName, gidLabels, cesName)
}

// Add or update CEP in cache, map to CES name, node name and associated CID
func (c *CESCache) upsertCEP(cepName CEPName, cesName CESName, nodeName NodeName, gidLabels string, cid CID) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	fmt.Println("upsertCEP called:", cepName, cesName, nodeName, gidLabels, cid)
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
	if cepData, ok := c.cepData[cepName]; ok {
		// If CEP was previously mapped to different CES, clear.
		if oldCES := cepData.ces; oldCES != cesName {
			c.cesData[oldCES].ceps.Delete(cepName)
		}

		// If CEP was previously mapped to different node, clear.
		if oldNode := cepData.node; oldNode != nodeName {
			c.nodeData[oldNode].ceps.Delete(cepName)
		}

		// If CEP was previously mapped to different labels, clear.
		if oldLabels := cepData.labels; oldLabels != gidLabels {
			c.globalIdLabelsToCIDSet[gidLabels].ceps.Delete(cepName)
			c.cleanLabelsMap(oldLabels)
		}
	}

	c.cepData[cepName] = &CEPData{
		ces:    cesName,
		node:   nodeName,
		labels: gidLabels,
	}

	c.cesData[cesName].ceps.Insert(cepName)

	if _, ok := c.nodeData[nodeName]; !ok {
		c.nodeData[nodeName] = &NodeData{
			ceps: sets.New[CEPName](),
		}
	}
	c.nodeData[nodeName].ceps.Insert(cepName)

	if _, ok := c.globalIdLabelsToCIDSet[gidLabels]; !ok {
		c.globalIdLabelsToCIDSet[gidLabels] = &SecIDs{
			ids:  sets.New[CID](),
			ceps: sets.New[CEPName](),
			// selectedID will be set when the first CID is inserted.
		}
	}
	c.globalIdLabelsToCIDSet[gidLabels].ceps.Insert(cepName)
}

// Update encryption key for node and return all affected CES whose CEPs are on that node.
func (c *CESCache) insertNode(nodeName NodeName, encryptionKey EncryptionKey) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	fmt.Println("insertNode called:", nodeName, encryptionKey)
	if _, ok := c.nodeData[nodeName]; !ok {
		c.nodeData[nodeName] = &NodeData{
			ceps: sets.New[CEPName](),
			key:  encryptionKey,
		}
		return nil
	}

	if c.nodeData[nodeName].key != encryptionKey {
		c.nodeData[nodeName].key = encryptionKey
		return c.getCESForCEPs(c.nodeData[nodeName].ceps)
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
	}

	c.cidToGidLabels[cid] = gidLabels
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

// Remove node from cache and return affected CES
func (c *CESCache) deleteNode(nodeName NodeName) []CESKey {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	fmt.Println("deleteNode called:", nodeName)
	if nodeData, ok := c.nodeData[nodeName]; ok {
		cesKeys := c.getCESForCEPs(nodeData.ceps)
		delete(c.nodeData, nodeName)
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
	if cepData, ok := c.cepData[cepName]; ok {
		return cepData.ces, true
	}
	return "", false
}

func (c *CESCache) hasCEP(cepName CEPName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cepData[cepName]
	return ok
}

func (c *CESCache) hasNode(nodeName NodeName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.nodeData[nodeName]
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

	c.cesData[cesName] = &CESData{
		ceps: sets.New[CEPName](),
		ns:   ns,
	}
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

func (c *CESCache) deleteNs(ns string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
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

func (c *CESCache) GetSelectedId(gid string) (CID, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if gidData, ok := c.globalIdLabelsToCIDSet[gid]; ok {
		return gidData.selectedID, true
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
