// Copyright 2016-2021 Authors of Cilium
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

package endpointbatch

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	cebNamePrefix      = "ceb"
	syncStateNever     = 0
	syncStatePartial   = 1
	syncStateDone      = 2
	maxCepsInCeb       = 100
	numRetries         = 5
	QueueCepByGreedy   = "Greedy"
	QueueCepByIdentity = "Identity"
)

var (
	apiServerBackoff = wait.Backoff{
		Steps:    4,
		Duration: 10 * time.Millisecond,
		Factor:   5.0,
		Jitter:   0.1,
	}
	cacheCep       = make(map[string]string)
	cacheCeb       = make(map[string]*CebBatch)
	cacheIdentity  = make(map[int64][]*CebBatch)
	QueueingMethod = QueueCepByIdentity
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "watchers")

type CebBatch struct {
	Ceb        *cilium_api_v2.CiliumEndpointBatch
	client     clientset.CiliumV2Interface
	StopCh     chan struct{}
	syncState  int
	syncPeriod time.Duration
	cebMutex   sync.Mutex
}

// Generate random string for given length of characters.
func randomName(n int) string {
	var letters = []rune("bcdfghjklmnpqrstvwxyz2456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// Get unique name for cebBatch
func uniqueCebBatchName(cnt int) string {
	cebName := fmt.Sprintf("%s-%s-%s", cebNamePrefix, randomName(cnt), randomName(4))
	for _, ok := cacheCeb[cebName]; ok; {
		cebName := fmt.Sprintf("%s-%s-%s", cebNamePrefix, randomName(cnt), randomName(4))
		_, ok = cacheCeb[cebName]
	}

	return cebName
}

// Create new CebBatch
func NewCebBatch(client clientset.CiliumV2Interface, name, identityID string) *CebBatch {
	var cebName string = name
	if name == "" {
		cebName = uniqueCebBatchName(10)
	}
	log.Debugf("Generated cebName:%s", cebName)
	ceb := &CebBatch{
		Ceb: &cilium_api_v2.CiliumEndpointBatch{
			TypeMeta: metav1.TypeMeta{
				Kind:       "CiliumEndpointBatch",
				APIVersion: cilium_api_v2.SchemeGroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: cebName,
				Annotations: map[string]string{
					annotation.IdentityID: identityID,
				},
			},
		},
		client:     client,
		StopCh:     make(chan struct{}),
		syncState:  syncStateNever,
		syncPeriod: 10 * time.Second,
	}

	return ceb
}

func (c *CebBatch) RunUntil() {
	// Retry updating upStream, until it sync timeout
	wait.PollImmediateUntil(c.syncPeriod, func() (bool, error) {

		// If local cached data is already synced to upstream
		// wait for new data
		if c.syncState == syncStateDone {
			return false, nil
		}
		// sync local cilium endpoint batch to upstream(APIServer)
		// If there is any error from ApiServer, keep trying.
		if err := c.updateCeb(); err != nil {
			log.WithError(err).Infof("Failed to update CEB on first attempt:%s\n", c.Ceb.GetName())
			if ok := c.onError(); ok != nil {
				return false, nil
			}
		}
		return false, nil
	}, c.StopCh)
}

func (c *CebBatch) onError() error {
	err := wait.ExponentialBackoff(apiServerBackoff, func() (bool, error) {
		log.Debugf("Retrying to update CEB:%s\n", c.Ceb.GetName())
		if ok := c.updateCeb(); ok != nil {
			log.WithError(ok).Infof("Failed to update CEB:%s\n", c.Ceb.GetName())
			return false, nil
		}
		return true, nil
	})
	return err
}

func (c *CebBatch) updateCeb() error {
	// Update existing ceb, if already exists one.
	var err, ok error
	var retCeb *cilium_api_v2.CiliumEndpointBatch
	if _, err = c.GetCiliumEndpointBatch(); err != nil {
		log.WithError(err).Debug("Error value from Get CiliumEndpointBatch")
	}
	if errors.IsNotFound(err) {
		log.Debugf("Creating a new CEB :%s\n", c.Ceb.GetName())
		if retCeb, ok = c.createCiliumEndpointBatch(); ok != nil {
			log.WithError(ok).Errorf("Error Creating CiliumEndpointBatch :%s", c.Ceb.GetName())
		}
	} else {
		log.Debugf("Updating the CEB :%s\n", c.Ceb.GetName())
		if retCeb, ok = c.updateCiliumEndpointBatch(); ok != nil {
			log.WithError(ok).Errorf("Error Updating CiliumEndpointBatch :%s", c.Ceb.GetName())
		}
	}

	c.Ceb.ObjectMeta = retCeb.ObjectMeta
	if ok == nil {
		c.cebMutex.Lock()
		if retCeb.DeepEqual(c.Ceb) {
			c.syncState = syncStateDone
		}
		c.cebMutex.Unlock()
		log.Debugf("Total number of CEPs: %d in CEB: %s\n",
			len(retCeb.Endpoints), retCeb.GetName())
	}
	return ok
}

// Create a cilium Endpoint Object
func (c *CebBatch) createCiliumEndpointBatch() (*cilium_api_v2.CiliumEndpointBatch, error) {
	return c.client.CiliumEndpointBatches().Create(context.TODO(), c.Ceb, metav1.CreateOptions{})
}

// Update the cilium Endpoint Object
func (c *CebBatch) updateCiliumEndpointBatch() (*cilium_api_v2.CiliumEndpointBatch, error) {
	return c.client.CiliumEndpointBatches().Update(context.TODO(), c.Ceb, metav1.UpdateOptions{})
}

// Delete the cilium Endpoint Object
func (c *CebBatch) DeleteCiliumEndpointBatch() error {
	return c.client.CiliumEndpointBatches().Delete(context.TODO(), c.Ceb.GetName(), metav1.DeleteOptions{})
}

// Delete the cilium Endpoint Object
func (c *CebBatch) GetCiliumEndpointBatch() (*cilium_api_v2.CiliumEndpointBatch, error) {
	return c.client.CiliumEndpointBatches().Get(context.TODO(), c.Ceb.GetName(), metav1.GetOptions{})
}

func BatchCepIntoCeb(client clientset.CiliumV2Interface, cep *cilium_v2.CoreCiliumEndpoint) error {

	// Check in local cache, if a given cep is already processed by one of the ceb.
	// and if exists, update a ceb with the new cep object in it.
	if cebName, ok := cacheCep[cep.Name]; ok {
		log.Debugf("Inserting CEP :%s in CEB: %s\n", cep.Name, cebName)
		queueCepInCeb(cep, cacheCeb[cebName])
		cacheCeb[cebName].syncState = syncStatePartial
		return nil
	}

	// find the matching ceb for the cep
	var ok error
	var ceb *CebBatch
	if QueueingMethod == QueueCepByIdentity {
		ceb, ok = getCebUsingIdentity(client, cep)
	} else {
		ceb, ok = getCeb(client, cep)
	}
	if ok != nil {
		log.WithError(ok).Errorf("Failed to get ceb for the cep: %s", cep.Name)
		return ok
	}

	// Update ceb in local cache and batch into the ceb
	cacheCep[cep.Name] = ceb.Ceb.GetName()
	queueCepInCeb(cep, ceb)
	ceb.syncState = syncStatePartial
	return nil
}

func getCeb(client clientset.CiliumV2Interface, cep *cilium_v2.CoreCiliumEndpoint) (*CebBatch, error) {

	// Get the first available CEB
	for _, cebBatch := range cacheCeb {
		if len(cebBatch.Ceb.Endpoints) == maxCepsInCeb {
			continue
		}
		return cebBatch, nil
	}

	// Allocate a newCebBatch, if there is no ceb available in existing pool of cebs
	newCeb := NewCebBatch(client, "", strconv.FormatInt(cep.IdentityID, 10))
	// Start the go routine, to monitor for any changes in CEB and sync with APIserver.
	// TODO: Implement error handling here
	cacheCeb[newCeb.Ceb.GetName()] = newCeb
	go newCeb.RunUntil()
	return newCeb, nil
}

func getCebUsingIdentity(client clientset.CiliumV2Interface, cep *cilium_v2.CoreCiliumEndpoint) (*CebBatch, error) {

	if cebs, ok := cacheIdentity[cep.IdentityID]; ok {
		for _, ceb := range cebs {
			if len(ceb.Ceb.Endpoints) < maxCepsInCeb {
				return ceb, nil
			}
		}
	}

	// If no match in existing ceb, allocate new CEB and cache it in cacheIdentity
	log.Debugf("Allocating newCeb for cep:%s", cep.Name)
	// Allocate a newCebBatch, if there is no ceb available in existing pool of cebs
	newCeb := NewCebBatch(client, "", strconv.FormatInt(cep.IdentityID, 10))
	// Start the go routine, to monitor for any changes in CEB and sync with APIserver.

	cacheIdentity[cep.IdentityID] = append(cacheIdentity[cep.IdentityID], newCeb)
	cacheCeb[newCeb.Ceb.GetName()] = newCeb
	go newCeb.RunUntil()
	return newCeb, nil

}
func queueCepInCeb(cep *cilium_v2.CoreCiliumEndpoint, cebBatch *CebBatch) {
	// If cep already exists in ceb, compare new cep with cached cep.
	// Update only if there is any change.
	for i, ep := range cebBatch.Ceb.Endpoints {
		if ep.Name == cep.Name {
			if cep.DeepEqual(&ep) {
				return
			}
			cebBatch.cebMutex.Lock()
			cebBatch.Ceb.Endpoints =
				append(cebBatch.Ceb.Endpoints[:i],
					cebBatch.Ceb.Endpoints[i+1:]...)
			cebBatch.cebMutex.Unlock()
			break
		}
	}

	log.Debugf("Queueing cep:%s into ceb:%s totalCepCount:%d", cep.Name, cebBatch.Ceb.GetName(),
		len(cebBatch.Ceb.Endpoints))
	cebBatch.cebMutex.Lock()
	cebBatch.Ceb.Endpoints =
		append(cebBatch.Ceb.Endpoints, *cep)
	cebBatch.cebMutex.Unlock()

	return
}

func RemoveCepFromCeb(cep *cilium_v2.CoreCiliumEndpoint) error {
	// Check in local cache, if a given cep is already batched in one of cebs.
	// and if exists, delete cep from ceb.
	if cebName, ok := cacheCep[cep.Name]; ok {
		ceb := cacheCeb[cebName]
		for i, ep := range ceb.Ceb.Endpoints {
			if ep.Name == cep.Name {
				ceb.cebMutex.Lock()
				ceb.Ceb.Endpoints =
					append(ceb.Ceb.Endpoints[:i],
						ceb.Ceb.Endpoints[i+1:]...)
				ceb.cebMutex.Unlock()
				break
			}
		}
		log.Debugf("Removed cep:%s from ceb:%s cepCount:%d", cep.Name, cebName,
			len(ceb.Ceb.Endpoints))
		delete(cacheCep, cep.Name)
		ceb.syncState = syncStatePartial
		if len(ceb.Ceb.Endpoints) == 0 {
			// Stop the subroutine
			close(ceb.StopCh)
			// Delete CEB in API server
			ceb.DeleteCiliumEndpointBatch()
			// Delete from cacheCeb
			delete(cacheCeb, cebName)
			// Remove ceb from other caches
			if QueueingMethod == QueueCepByIdentity {
				if cebs, ok := cacheIdentity[cep.IdentityID]; ok {
					for i, ceb := range cebs {
						if ceb.Ceb.GetName() == cebName {
							cacheIdentity[cep.IdentityID] =
								append(cacheIdentity[cep.IdentityID][:i],
									cacheIdentity[cep.IdentityID][i+1:]...)
						}
					}
				}
				if len(cacheIdentity[cep.IdentityID]) == 0 {
					delete(cacheIdentity, cep.IdentityID)
				}
			}
		}
	}

	return nil

}

func CiliumEndpointBatchSyncLocal(client clientset.CiliumV2Interface) {
	// List all CEB's from ApiServer
	var err error
	var cebs *cilium_v2.CiliumEndpointBatchList
	log.Debug("Called CiliumEndpointBatchSyncLocal\n")
	// Read CEB from APIserver
	for i := 0; i < numRetries; i++ {
		cebs, err = client.CiliumEndpointBatches().List(context.Background(), meta_v1.ListOptions{})
		if err == nil {
			break
		}
		if err != nil && (errors.IsServerTimeout(err) || errors.IsTimeout(err)) {
			log.WithError(err).Infof("Failed to get Cilium Endpoint batch list from Apiserver, retry count :%d", i+1)
			continue
		}
		// TODO Do we need to handle other errors?
	}

	// Nothing to process, return.
	if err != nil {
		log.WithError(err).Error("Multiple retries failed to get Cilium Endpoint batch list from Apiserver")
		return
	}

	// If there are no CEBs in datastore, nothing to be done.
	if len(cebs.Items) == 0 {
		log.Debug("No CEB objects in datastore\n")
		return
	}

	for _, ceb := range cebs.Items {
		cebName := ceb.GetName()
		if _, ok := cacheCeb[cebName]; !ok {
			cacheCeb[cebName] = NewCebBatch(client, cebName, "")
		}
		for _, cep := range ceb.Endpoints {
			cacheCep[cep.Name] = cebName
			queueCepInCeb(&cep, cacheCeb[cebName])
		}
		// ResourceVersion of object is required to Update the CEB object
		cacheCeb[cebName].Ceb.ObjectMeta = ceb.ObjectMeta
		go cacheCeb[cebName].RunUntil()
	}
	// List all ceps from datastore, remove stale entries present in CEB
	// for example, some CEP entries are deleted in datastore, but it was
	// not yet updated in CEB.
	var ceps *cilium_v2.CiliumEndpointList
	for i := 0; i < numRetries; i++ {
		ceps, err = client.CiliumEndpoints("").List(context.Background(), meta_v1.ListOptions{})
		if err == nil {
			break
		}
		if err != nil && (errors.IsServerTimeout(err) || errors.IsTimeout(err)) {
			log.WithError(err).Infof("Failed to get Cilium Endpoint list from Apiserver, retry count :%d", i+1)
			continue
		}
	}
	// Nothing to process, return.
	if err != nil {
		log.WithError(err).Error("Multiple retries failed to get Cilium Endpoint list from Apiserver")
		return
	}

	actualCepList := make(map[string]*cilium_v2.CoreCiliumEndpoint)
	for _, cep := range ceps.Items {
		actualCepList[cep.Name] = ConvertCeptoCoreCep(&cep)
	}

	// Remove stale entries present in local cache
	for cepName, cebName := range cacheCep {
		if _, ok := actualCepList[cepName]; !ok {
			for i, cep := range cacheCeb[cebName].Ceb.Endpoints {
				if cep.Name == cepName {
					RemoveCepFromCeb(&cacheCeb[cebName].Ceb.Endpoints[i])
				}
			}
		}
	}

	return
}

func ConvertCeptoCoreCep(cep *cilium_v2.CiliumEndpoint) *cilium_v2.CoreCiliumEndpoint {
	// Copy Networking field into core CEP
	epNetworking := new(cilium_api_v2.EndpointNetworking)
	cep.Status.Networking.DeepCopyInto(epNetworking)
	// Copy NamedPorts entries into core CEP
	namedPorts := make(models.NamedPorts, len(cep.Status.NamedPorts))
	for i := range cep.Status.NamedPorts {
		if cep.Status.NamedPorts[i] != nil {
			namedPorts[i] = new(models.Port)
			namedPorts[i] = cep.Status.NamedPorts[i]
		}
	}
	var identityID int64 = 0
	if cep.Status.Identity != nil {
		identityID = cep.Status.Identity.ID
	}
	return &cilium_api_v2.CoreCiliumEndpoint{
		Name:       cep.GetName(),
		Namespace:  cep.Namespace,
		Networking: epNetworking,
		Encryption: cep.Status.Encryption,
		IdentityID: identityID,
	}

}
