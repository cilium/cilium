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

import (
	"fmt"
	"math/rand"
	"time"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/annotation"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	// sequentialLetters contains lower case alphabets without vowels and few numbers.
	// skipped vowels and numbers [0, 1] to avoid generating controversial names.
	sequentialLetters = []rune("bcdfghjklmnpqrstvwxyz2456789")
)

// ceBatch holds local copy of CiliumEndpointBatch.
type ceBatch struct {
	ceb          *cilium_v2.CiliumEndpointBatch
	backendMutex lock.RWMutex
}

// cebManager
type cebManager interface {
	InsertCepInCache(cep *cilium_v2.CoreCiliumEndpoint) (string, error)
	RemoveCepFromCache(cep *cilium_v2.CoreCiliumEndpoint) error
	getCebFromCache(cebName string) (*cilium_v2.CiliumEndpointBatch, error)
	findCeb(cep *cilium_v2.CoreCiliumEndpoint) (*ceBatch, bool)
	updateCebInCache(ceb *cilium_v2.CiliumEndpointBatch, deepCopy bool)
	deleteCebFromCache(cebName string)
	createCeb(name string) *ceBatch
	getCepCount() int
	getCebCount() int
	getAllCeps() map[string]*cilium_v2.CoreCiliumEndpoint
}

// Implementation of FirstComeFirstServe batching mode. If new CEP is inserted,
// then the CEP is queued in any one of the available CEB. CEPs are inserted into
// CEBs without any preference or any priority.
type cebManagerFcfs struct {

	// cacheCepMap is used to map cepName to cebName
	cacheCepMap *cepToCebMapping

	// cacheCeb is used to map cebName to ceBatch object.
	cacheCeb map[string]*ceBatch

	// Aggregator is an interface, as CEPs are inserted or removed in a CEB,
	// this would keep track of changes happen to a CEB and resolve them into
	// a single actionable change.
	cebsToSync *aggregator

	// maxCepsInCeb is the maximum number of CiliumCoreEndpoint(s) packed in
	// a CiliumEndpointBatch Resource.
	maxCepsInCeb int
}

// Create and Intialize a new FCFS based manager
func newCebManagerFcfs(cebSync *aggregator, maxCepsInCeb int) cebManager {
	return &cebManagerFcfs{
		cacheCeb:     make(map[string]*ceBatch),
		cebsToSync:   cebSync,
		cacheCepMap:  newCepToCebMapping(),
		maxCepsInCeb: maxCepsInCeb,
	}
}

// queueCep insert the CEP in a CEB, if the CEP already exists in a CEB
// it replaces with new CEP.
func queueCep(cep *cilium_v2.CoreCiliumEndpoint, ceBatch *ceBatch) {
	// If cep already exists in ceb, compare new cep with cached cep.
	// Update only if there is any change.
	for i, ep := range ceBatch.ceb.Endpoints {
		if ep.Name == cep.Name && ep.Namespace == cep.Namespace {
			if cep.DeepEqual(&ep) {
				return
			}
			// Remove the matched cep from list.
			ceBatch.backendMutex.Lock()
			ceBatch.ceb.Endpoints =
				append(ceBatch.ceb.Endpoints[:i],
					ceBatch.ceb.Endpoints[i+1:]...)
			ceBatch.backendMutex.Unlock()
			break
		}
	}

	log.Debugf("Queueing cep:%s into ceb:%s totalCepCount:%d", cep.Name, ceBatch.ceb.GetName(),
		len(ceBatch.ceb.Endpoints))
	// Insert the cep in list
	ceBatch.backendMutex.Lock()
	ceBatch.ceb.Endpoints =
		append(ceBatch.ceb.Endpoints, *cep)
	ceBatch.backendMutex.Unlock()

	return
}

// Generate random string for given length of characters.
func randomName(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = sequentialLetters[rand.Intn(len(sequentialLetters))]
	}
	return string(b)
}

// Generates unique random name for the CiliumEndpointBatch, the format
// of a CEB name is similiar to pod k8s naming convention "ceb-123456789-abcd".
// First 3 letters indicates ceb resource, followed by random letters.
func uniqueCeBatchName(cacheCeb map[string]*ceBatch) string {
	rand.Seed(time.Now().UnixNano())
	var ok bool
	var cebName string
	cebName = fmt.Sprintf("%s-%s-%s", cebNamePrefix, randomName(9), randomName(4))
	for _, ok = cacheCeb[cebName]; ok; {
		cebName = fmt.Sprintf("%s-%s-%s", cebNamePrefix, randomName(9), randomName(4))
		_, ok = cacheCeb[cebName]
	}

	return cebName
}

// createCeb function create a new ceb and capacity to hold maximum ceps in a CEB.
// This function called on 2 different scenarios.
// 1) During runtime, when ceb manager decides to create a new ceb, it call
//    with empty name. Function generates random unique name and assign it to CEB
// 2) During operator warm boot [after crash or software upgrade], batching manager
//    create CEB, by passing unique name.
func (c *cebManagerFcfs) createCeb(name string) *ceBatch {
	var cebName string = name
	if name == "" {
		cebName = uniqueCeBatchName(c.cacheCeb)
	}
	ceb := &ceBatch{
		ceb: &cilium_v2.CiliumEndpointBatch{
			TypeMeta: meta_v1.TypeMeta{
				Kind:       "CiliumEndpointBatch",
				APIVersion: cilium_v2.SchemeGroupVersion.String(),
			},
			ObjectMeta: meta_v1.ObjectMeta{
				Name: cebName,
				Annotations: map[string]string{
					annotation.CiliumEndpointBatchQueueInfo: CEBatchingModeFcfs,
				},
			},
			Endpoints: make([]cilium_v2.CoreCiliumEndpoint, 0, c.maxCepsInCeb),
		},
	}
	c.cacheCeb[cebName] = ceb
	log.Debugf("Generated cebName:%s", cebName)
	return ceb
}

// If available, remove Ceb object from cache. deleteCebFromCache called after successfull removal from
// apiserver.
func (c *cebManagerFcfs) deleteCebFromCache(cebName string) {
	if _, ok := c.cacheCeb[cebName]; !ok {
		log.Debugf("Failed to retrieve Ceb object in local cache. cebName:%s", cebName)
		return
	}
	delete(c.cacheCeb, cebName)
}

// updateCebInCache function copies the ciliumEndpoint object in local cache. if isDeepCopy flag is set,
// whole CoreCiliumEndpoint object stored in local cache.
// There are two scenarios updateCebInCache is called.
// 1) During operator warm boot[after crash or software upgrade], CEB controller sync CEB states from
// api-server to cache. In this case, isDeepCopy set to true to copy entire CEP object locally.
// 2) During runtime, reconciler sync curremt state with API server and update meta header only.
// isDeepCopy flag is set to false.
func (c *cebManagerFcfs) updateCebInCache(srcCeb *cilium_v2.CiliumEndpointBatch, isDeepCopy bool) {
	if ceb, ok := c.cacheCeb[srcCeb.GetName()]; ok {
		if !isDeepCopy {
			ceb.ceb.ObjectMeta = srcCeb.ObjectMeta
		} else {
			srcCeb.DeepCopyInto(ceb.ceb)
			for _, cep := range ceb.ceb.Endpoints {
				// Update the cacheCepMap, to reflect all CEPs are packed in a CEB
				c.cacheCepMap.insert(getCepNameFromCCEP(&cep), srcCeb.GetName())
			}
		}
	}
}

// If available, getCebFromCache returns CiliumEndpointBatch object.
func (c *cebManagerFcfs) getCebFromCache(cebName string) (*cilium_v2.CiliumEndpointBatch, error) {
	if ceb, ok := c.cacheCeb[cebName]; ok {
		outCeb := new(cilium_v2.CiliumEndpointBatch)
		ceb.backendMutex.Lock()
		ceb.ceb.DeepCopyInto(outCeb)
		ceb.backendMutex.Unlock()
		return outCeb, nil

	}
	return nil, fmt.Errorf("Failed to get CEB from local cache for the cebName: %s", cebName)
}

// findCeb returns the available ceBatch object for a CEP, CEB is choosen based on FCFS.
// if all CEB's reached max capacity or marked for delete. Allocate a new CEB.
// if new ceBatch is created, it returns ceBatch object and true
// else return existing ceBatch and false.
func (c *cebManagerFcfs) findCeb(cep *cilium_v2.CoreCiliumEndpoint) (*ceBatch, bool) {

	// Get the first available CEB
	for _, ceb := range c.cacheCeb {
		// Note: If CEB's is marked for delete or no CEP's present in it don't add
		// any more new CEP's in it.
		if len(ceb.ceb.Endpoints) >= c.maxCepsInCeb || len(ceb.ceb.Endpoints) == 0 ||
			c.cebsToSync.isCebMarkedForDelete(ceb.ceb.GetName()) {
			continue
		}
		return ceb, false
	}

	// Allocate a new ceBatch and return
	return c.createCeb(""), true
}

// InsertCepInCache is used to Insert CEP in local cache, this may result in Creating a New
// CEB object or Updating an existing CEB object.
func (c *cebManagerFcfs) InsertCepInCache(cep *cilium_v2.CoreCiliumEndpoint) (string, error) {

	// Check the given cep is already packed in any of the CEB.
	// if yes, Update a ceb with the given cep object.
	if cebName, ok := c.cacheCepMap.get(getCepNameFromCCEP(cep)); ok {
		queueCep(cep, c.cacheCeb[cebName])
		c.cebsToSync.updateAggregator(cebName, CebUpdate)
		return cebName, nil
	}

	cb, isNewCeb := c.findCeb(cep)

	// Cache CEP name with newly allocated CEB.
	c.cacheCepMap.insert(getCepNameFromCCEP(cep), cb.ceb.GetName())

	// Queue the CEP in CEB
	queueCep(cep, cb)

	// If it isNewCeb, update Aggregator to create a ceb
	if isNewCeb {
		c.cebsToSync.updateAggregator(cb.ceb.GetName(), CebCreate)
		return cb.ceb.GetName(), nil
	}

	c.cebsToSync.updateAggregator(cb.ceb.GetName(), CebUpdate)
	return cb.ceb.GetName(), nil
}

// RemoveCepInCache is used to remove CEP from local cache, this may result in Deleting a
// CEB object or Updating an existing CEB object.
func (c *cebManagerFcfs) RemoveCepFromCache(cep *cilium_v2.CoreCiliumEndpoint) error {

	// Check in local cache, if a given cep is already batched in one of the ceb.
	// and if exists, delete cep from ceb.
	cepName := getCepNameFromCCEP(cep)
	log.Debugf("Remove CEP from local cache :%s", cepName)
	if cebName, ok := c.cacheCepMap.get(cepName); ok {
		ceb, err := c.cacheCeb[cebName]
		if err {
			if ceb == nil || ceb.ceb == nil {
				log.Infof("Valid cep Mapping, but no matching CEP in CEB")
				return nil
			}
		}

		for i, ep := range ceb.ceb.Endpoints {
			if ep.Name == cep.Name && ep.Namespace == cep.Namespace {
				ceb.backendMutex.Lock()
				ceb.ceb.Endpoints =
					append(ceb.ceb.Endpoints[:i],
						ceb.ceb.Endpoints[i+1:]...)
				ceb.backendMutex.Unlock()
				break
			}
		}
		log.Debugf("Removed cep:%s from ceb:%s cepCount:%d", cepName, cebName,
			len(ceb.ceb.Endpoints))

		c.cacheCepMap.deleteCep(cepName)

		if len(ceb.ceb.Endpoints) == 0 {
			log.Debugf("Remove CEB from local cache :%s", cebName)
			c.cebsToSync.updateAggregator(cebName, CebDelete)
			return nil
		}

		c.cebsToSync.updateAggregator(cebName, CebLazyUpdate)
		return nil
	}

	return nil
}

// Return the total count of CEP
func (c *cebManagerFcfs) getCepCount() int {
	cnt := 0
	for _, ceb := range c.cacheCeb {
		cnt += len(ceb.ceb.Endpoints)
	}
	return cnt
}

// Return the total count of CEB
func (c *cebManagerFcfs) getCebCount() int {
	return len(c.cacheCeb)
}

// Return list of Core CEPs
func (c *cebManagerFcfs) getAllCeps() map[string]*cilium_v2.CoreCiliumEndpoint {
	ceps := make(map[string]*cilium_v2.CoreCiliumEndpoint)
	for _, ceb := range c.cacheCeb {
		for _, cep := range ceb.ceb.Endpoints {
			ceps[getCepNameFromCCEP(&cep)] = cep.DeepCopy()
		}
	}

	return ceps
}
