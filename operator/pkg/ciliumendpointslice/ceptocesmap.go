// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"k8s.io/apimachinery/pkg/util/sets"

	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
)

type CEPName resource.Key
type CESKey resource.Key
type CESName string

// CESData contains all CES data, including endpoints.
// CES is reconciled to have endpoints equal to CEPs mapped to it
// and other fields set from the CESData.
type CESData struct {
	ceps sets.Set[CEPName]
	ns   string
}

// Initializes CESData with given namespace
func NewCESData(ns string) *CESData {
	return &CESData{
		ceps: sets.New[CEPName](),
		ns:   ns,
	}
}

// CESToCEPMapping is used to map Cilium Endpoints to CiliumEndpointSlices and
// retrieving all the Cilium Endpoints mapped to the given CiliumEndpointSlice.
// This map is protected by lock for consistent and concurrent access.
type CESToCEPMapping struct {
	mutex lock.RWMutex
	// cepNameToCESName is used to map CiliumEndpoint name to CiliumEndpointSlice name.
	cepNameToCESName map[CEPName]CESName
	// cesNameToData is used to map CiliumEndpointSlice name to all CiliumEndpoints names it contains
	// and the namespace associated with it
	cesNameToData map[CESName]*CESData
}

// Creates and intializes the new CESToCEPMapping
func newCESToCEPMapping() *CESToCEPMapping {
	return &CESToCEPMapping{
		cepNameToCESName: make(map[CEPName]CESName),
		cesNameToData:    make(map[CESName]*CESData),
	}
}

// Insert the CEP in cache, map CEP name to CES name
func (c *CESToCEPMapping) insertCEP(cepName CEPName, cesName CESName) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cepNameToCESName[cepName] = cesName
	c.cesNameToData[cesName].ceps.Insert(cepName)
}

// Remove the CEP entry from map
func (c *CESToCEPMapping) deleteCEP(cepName CEPName) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cesNameToData[c.cepNameToCESName[cepName]].ceps.Delete(cepName)
	delete(c.cepNameToCESName, cepName)
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

	if cesData, ok := c.cesNameToData[ces]; ok {
		return cesData.ceps.Len()
	}
	return 0
}

// Return CEP Names mapped to the given CES
func (c *CESToCEPMapping) getCEPsInCES(ces CESName) []CEPName {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if cesData, ok := c.cesNameToData[ces]; ok {
		return cesData.ceps.UnsortedList()
	}
	return nil
}

// Initializes mapping structure for CES
func (c *CESToCEPMapping) insertCES(cesName CESName, ns string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cesNameToData[cesName] = &CESData{
		ceps: sets.New[CEPName](),
		ns:   ns,
	}
}

// Remove mapping structure for CES
func (c *CESToCEPMapping) deleteCES(cesName CESName) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.cesNameToData, cesName)
}

func (c *CESToCEPMapping) hasCESName(cesName CESName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cesNameToData[cesName]
	return ok
}

// Return the total number of CESs.
func (c *CESToCEPMapping) getCESCount() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cesNameToData)
}

// Return names of all CESs.
func (c *CESToCEPMapping) getAllCESs() []CESName {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	cess := make([]CESName, 0, len(c.cesNameToData))
	for ces := range c.cesNameToData {
		cess = append(cess, ces)
	}
	return cess
}

// Return the namespace of the given CES
func (c *CESToCEPMapping) getCESNamespace(name CESName) string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if cesData, ok := c.cesNameToData[name]; ok {
		return cesData.ns
	}
	return ""
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
