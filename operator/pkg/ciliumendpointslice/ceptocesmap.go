// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import "github.com/cilium/cilium/pkg/lock"

type CEPName string
type CESName string

// CESToCEPMapping is used to map CiliumEndpointSlice name to cesTracker object
// which in turn consists of CEPs, a CES name to list of all CEPs.
// Also, it manages a map CEP name to CES name.
// These maps are used by the CES manager, primarily used for storing and retrieving
// the desired CESs by thread-safe.
// This map is protected by lock for consistent and concurrent access.
type CESToCEPMapping struct {
	cesMutex lock.RWMutex
	// cepNametoCESName is used to map CiliumEndpoint name to CiliumEndpointSlice name.
	cepNametoCESName map[CEPName]CESName
	// desiredCESs is used to map cesName to cesTracker object.
	desiredCESs map[CESName]*cesTracker
}

// Creates and intializes the new CESToCEPMapping
func newDesiredCESMap() *CESToCEPMapping {
	return &CESToCEPMapping{
		desiredCESs:      make(map[CESName]*cesTracker),
		cepNametoCESName: make(map[CEPName]CESName),
	}
}

// Insert the CEP in cache, map CEP name to CES name
func (c *CESToCEPMapping) insertCEP(cepName, cesName string) {
	c.cesMutex.Lock()
	defer c.cesMutex.Unlock()
	c.cepNametoCESName[CEPName(cepName)] = CESName(cesName)
}

// Remove the CEP entry from map
func (c *CESToCEPMapping) deleteCEP(cepName string) {
	c.cesMutex.Lock()
	defer c.cesMutex.Unlock()
	delete(c.cepNametoCESName, CEPName(cepName))
}

func (c *CESToCEPMapping) getCESName(cepName string) (string, bool) {
	c.cesMutex.RLock()
	defer c.cesMutex.RUnlock()
	name, ok := c.cepNametoCESName[CEPName(cepName)]
	return string(name), ok
}

func (c *CESToCEPMapping) hasCEP(cepName string) bool {
	c.cesMutex.RLock()
	defer c.cesMutex.RUnlock()
	_, ok := c.cepNametoCESName[CEPName(cepName)]
	return ok
}

// Return total number of CEPs stored in cache
func (c *CESToCEPMapping) countCEPs() int {
	c.cesMutex.RLock()
	defer c.cesMutex.RUnlock()
	return len(c.cepNametoCESName)
}

// Insert the CES tracker in map
func (c *CESToCEPMapping) insertCES(cesName string, ces *cesTracker) {
	c.cesMutex.Lock()
	defer c.cesMutex.Unlock()
	c.desiredCESs[CESName(cesName)] = ces
}

// Remove the CES tracker from map
func (c *CESToCEPMapping) deleteCES(cesName string) {
	c.cesMutex.Lock()
	defer c.cesMutex.Unlock()
	delete(c.desiredCESs, CESName(cesName))
}

func (c *CESToCEPMapping) getCESTracker(cesName string) (*cesTracker, bool) {
	c.cesMutex.RLock()
	defer c.cesMutex.RUnlock()
	ces, ok := c.desiredCESs[CESName(cesName)]
	return ces, ok
}

func (c *CESToCEPMapping) getAllCESs() []*cesTracker {
	c.cesMutex.RLock()
	defer c.cesMutex.RUnlock()
	var cess []*cesTracker
	for _, ces := range c.desiredCESs {
		cess = append(cess, ces)
	}
	return cess
}

func (c *CESToCEPMapping) hasCESName(cesName string) bool {
	c.cesMutex.RLock()
	defer c.cesMutex.RUnlock()
	_, ok := c.desiredCESs[CESName(cesName)]
	return ok
}

// Return the total number of desired CESs.
func (c *CESToCEPMapping) getCESCount() int {
	c.cesMutex.RLock()
	defer c.cesMutex.RUnlock()
	return len(c.desiredCESs)
}
