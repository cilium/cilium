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

// Create and initialize new cepToCebMapping
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
