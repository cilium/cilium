// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ciliumendpointbatch

import "github.com/cilium/cilium/pkg/lock"

type CEPName string
type CEBName string

// CEBToCEPMapping is used to map CiliumEndpointBatch name to cebTracker object
// which in turn consists of CEPs, a CEB name to list of all CEPs.
// Also, it manages a map CEP name to CEB name.
// These maps are used by the CEB manager, primarily used for storing and retrieving
// the desired CEBs by thread-safe.
// This map is protected by lock for consistent and concurrent access.
type CEBToCEPMapping struct {
	cebMutex lock.RWMutex
	// cepNametoCEBName is used to map CiliumEndpoint name to CiliumEndpointBatch name.
	cepNametoCEBName map[CEPName]CEBName
	// desiredCEBs is used to map cebName to cebTracker object.
	desiredCEBs map[CEBName]*cebTracker
}

// Creates and intializes the new CEBToCEPMapping
func newDesiredCebMap() *CEBToCEPMapping {
	return &CEBToCEPMapping{
		desiredCEBs:      make(map[CEBName]*cebTracker),
		cepNametoCEBName: make(map[CEPName]CEBName),
	}
}

// Insert the CEP in cache, map CEP name to CEB name
func (c *CEBToCEPMapping) insertCEP(cepName, cebName string) {
	c.cebMutex.Lock()
	defer c.cebMutex.Unlock()
	c.cepNametoCEBName[CEPName(cepName)] = CEBName(cebName)
}

// Remove the CEP entry from map
func (c *CEBToCEPMapping) deleteCEP(cepName string) {
	c.cebMutex.Lock()
	defer c.cebMutex.Unlock()
	delete(c.cepNametoCEBName, CEPName(cepName))
}

func (c *CEBToCEPMapping) getCEBName(cepName string) (string, bool) {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	name, ok := c.cepNametoCEBName[CEPName(cepName)]
	return string(name), ok
}

func (c *CEBToCEPMapping) hasCEP(cepName string) bool {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	_, ok := c.cepNametoCEBName[CEPName(cepName)]
	return ok
}

// Return total number of CEPs stored in cache
func (c *CEBToCEPMapping) countCEPs() int {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	return len(c.cepNametoCEBName)
}

// Insert the CEB tracker in map
func (c *CEBToCEPMapping) insertCEB(cebName string, ceb *cebTracker) {
	c.cebMutex.Lock()
	defer c.cebMutex.Unlock()
	c.desiredCEBs[CEBName(cebName)] = ceb
}

// Remove the CEB tracker from map
func (c *CEBToCEPMapping) deleteCEB(cebName string) {
	c.cebMutex.Lock()
	defer c.cebMutex.Unlock()
	delete(c.desiredCEBs, CEBName(cebName))
}

func (c *CEBToCEPMapping) getCEBTracker(cebName string) (*cebTracker, bool) {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	ceb, ok := c.desiredCEBs[CEBName(cebName)]
	return ceb, ok
}

func (c *CEBToCEPMapping) getCEBTrackerOnly(cebName string) *cebTracker {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	return c.desiredCEBs[CEBName(cebName)]
}

func (c *CEBToCEPMapping) getAllCEBs() []*cebTracker {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	var cebs []*cebTracker
	for _, ceb := range c.desiredCEBs {
		cebs = append(cebs, ceb)
	}
	return cebs
}

func (c *CEBToCEPMapping) hasCEBName(cebName string) bool {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	_, ok := c.desiredCEBs[CEBName(cebName)]
	return ok
}

// Return the total number of desired CEBs.
func (c *CEBToCEPMapping) getCEBCount() int {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	return len(c.desiredCEBs)
}
