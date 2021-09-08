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

// cepToCebMapping is used to map CiliumEndpoint name to CiliumEndpointBatch name.
// This is used by CEB manager, for every CEP Insertion/Removal CEB Controller
// use this map to find in which CEB the CEP is queued.
// This map is protected by lock for consistent and concurrent access.
type cepToCebMapping struct {
	cepMutex lock.RWMutex
	cacheCep map[CEPName]CEBName
}

// Creates and initializes new cepToCebMapping
func newCepToCebMapping() *cepToCebMapping {
	return &cepToCebMapping{
		cacheCep: make(map[CEPName]CEBName),
	}
}

// Insert the CEP in cache, map CEP name to CEB name
func (c *cepToCebMapping) insert(cepName, cebName string) {
	c.cepMutex.Lock()
	defer c.cepMutex.Unlock()
	c.cacheCep[CEPName(cepName)] = CEBName(cebName)
}

// Remove the CEP entry from map
func (c *cepToCebMapping) deleteCep(cepName string) {
	c.cepMutex.Lock()
	defer c.cepMutex.Unlock()
	delete(c.cacheCep, CEPName(cepName))
}

func (c *cepToCebMapping) get(cepName string) (string, bool) {
	c.cepMutex.RLock()
	defer c.cepMutex.RUnlock()
	name, ok := c.cacheCep[CEPName(cepName)]
	return string(name), ok
}

func (c *cepToCebMapping) has(cepName string) bool {
	c.cepMutex.RLock()
	defer c.cepMutex.RUnlock()
	_, ok := c.cacheCep[CEPName(cepName)]
	return ok
}

// Return total number of CEPs stored in cache
func (c *cepToCebMapping) count() int {
	c.cepMutex.RLock()
	defer c.cepMutex.RUnlock()
	return len(c.cacheCep)
}

// desiredCebMapping is used to map CiliumEndpointBatch name to cebTracker object.
// This map is used by the CEB manager, primarily used for storing and retrieving
// the desired CEBs by thread-safe.
// This map is protected by lock for consistent and concurrent access.
type desiredCebMapping struct {
	cebMutex lock.RWMutex
	// desiredCebs is used to map cebName to cebTracker object.
	desiredCebs map[CEBName]*cebTracker
}

// Creates and intializes the new desiredCebMapping
func newDesiredCebMap() *desiredCebMapping {
	return &desiredCebMapping{
		desiredCebs: make(map[CEBName]*cebTracker),
	}
}

// Insert the CEB tracker in map
func (c *desiredCebMapping) insert(cebName string, ceb *cebTracker) {
	c.cebMutex.Lock()
	defer c.cebMutex.Unlock()
	c.desiredCebs[CEBName(cebName)] = ceb
}

// Remove the CEB tracker from map
func (c *desiredCebMapping) deleteCeb(cebName string) {
	c.cebMutex.Lock()
	defer c.cebMutex.Unlock()
	delete(c.desiredCebs, CEBName(cebName))
}

func (c *desiredCebMapping) get(cebName string) (*cebTracker, bool) {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	ceb, ok := c.desiredCebs[CEBName(cebName)]
	return ceb, ok
}

func (c *desiredCebMapping) getCeb(cebName string) *cebTracker {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	return c.desiredCebs[CEBName(cebName)]
}

func (c *desiredCebMapping) getAllCebs() []*cebTracker {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	var cebs []*cebTracker
	for _, ceb := range c.desiredCebs {
		cebs = append(cebs, ceb)
	}
	return cebs
}

func (c *desiredCebMapping) has(cebName string) bool {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	_, ok := c.desiredCebs[CEBName(cebName)]
	return ok
}

// Return the total number of desired CEBs count.
func (c *desiredCebMapping) cnt() int {
	c.cebMutex.RLock()
	defer c.cebMutex.RUnlock()
	return len(c.desiredCebs)
}
