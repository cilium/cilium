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
	"context"
	"time"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/k8s"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	csv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	csv2a1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// cebNamePrefix is the prefix name for added for CiliumEndpointBatch
	// resource.
	cebNamePrefix = "ceb"

	// maxRetries is the number of times a service will be retried before it is
	// dropped.
	maxRetries = 3

	// CEPs are queued in a CEB as FirstComeFirstServe, CEPs are packed in random order.
	CEBatchingModeFcfs = "cebModeFcfs"
)

var (
	// apiServerBackoff creates a new API Machinery backoff parameter.
	apiServerBackoff = wait.Backoff{
		// Return a exponential backoff configuration, return total duration of ~2 second.
		// Example, 0s, 0.055s, 0.320s, 1.65s
		// Maximum number of retries is 4
		Steps:    4,
		Duration: 50 * time.Millisecond,
		Factor:   5.0,
		Jitter:   0.1,
	}
)

type CiliumEndpointBatchController struct {
	// Cilium kubernetes clients to access V2 and V2alpha1 resources
	clientV2   csv2.CiliumV2Interface
	clientV2a1 csv2a1.CiliumV2alpha1Interface

	// aggregator, is an util used to order the list of CEB that needs to reconciled with API server.
	aggregator *aggregator

	// reconciler is an util used to reconcile CiliumEndpointBatch changes.
	reconciler *reconciler

	// Manager is used to create and maintain local datastore. Manager watches for
	// cilium endpoint changes and enqueue/dequeue the cilium endpoint changes in CEB.
	// It maintains the desired state of CEBs in dataStore
	Manager cebManager

	// cebDeleteSyncTime is used track latency between CEBatchDeleteSyncPeriod. if the latency
	// exceeds CEBatchDeleteSyncPeriod it would let reconcile all CEB's [create, update and delete]
	// with k8s-apiServer.
	cebDeleteSyncTime time.Duration

	// ciliumEndpointStore is used to list of current active CEPs in a cluster. By, using this cache
	// we could avoid costly api calls going to k8s-apiserver.
	ciliumEndpointStore cache.Indexer

	// ciliumEndpointBatchUpsertSyncPeriod indicates the minimum delay period for the
	// some CiliumEndpointBatches to sync with k8s APIserver. Newly created and
	// updated CiliumEndpointBatches are synced after this interval.
	// Below listed cases used for syncing Update CiliumEndpointBatches.
	// 1) Insert new CEPs in a CEB.
	// 2) Modify existing CEPs in a CEB.
	ciliumEndpointBatchUpsertSyncPeriod time.Duration

	// ciliumEndpointBatchDeleteSync indicates the minimum delay period for syncing
	// some CiliumEndpointBatches with k8s APIserver. Deleted CEB's and
	// updated CiliumEndpointBatches are synced after this interval.
	// Below listed case used for syncing Update CiliumEndpointBatches.
	// 1) Remove CEPs in a CEB.
	ciliumEndpointBatchDeleteSyncPeriod time.Duration
}

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ciliumEndpointBatch")

// Derives the unique name from CiliumEndpoint object.
// This unique name is used for mapping CiliumEndpoint to CiliumEndpointBatch.
// Used widely, to determine the given CEP is mapped to any CEB or not.
func getCepNameFromCEP(cep *capi_v2.CiliumEndpoint) string {
	return cep.Name + cep.Namespace
}

// Derives the unique name from CoreCiliumEndpoint object.
func getCepNameFromCCEP(cep *capi_v2a1.CoreCiliumEndpoint) string {
	return cep.Name + cep.Namespace
}

// NewCebController, Creates and initializes the CEB controller
func NewCebController(client *k8s.K8sCiliumClient,
	cebSyncPeriod time.Duration,
	cebDeleteSyncPeriod time.Duration,
	maxCepsInCeb int,
) *CiliumEndpointBatchController {

	var manager cebManager

	aggregator := newAggregator()

	manager = newCebManagerFcfs(aggregator, maxCepsInCeb)

	cebC := &CiliumEndpointBatchController{
		clientV2:                            client.CiliumV2(),
		clientV2a1:                          client.CiliumV2alpha1(),
		aggregator:                          aggregator,
		reconciler:                          newReconciler(client.CiliumV2alpha1(), manager),
		Manager:                             manager,
		cebDeleteSyncTime:                   0,
		ciliumEndpointBatchUpsertSyncPeriod: cebSyncPeriod,
		ciliumEndpointBatchDeleteSyncPeriod: cebDeleteSyncPeriod,
	}

	// List all existing CEBs from API server and cache it locally.
	// This sync should happen before starting CEP watcher, because CEP watcher
	// notifies the existing CEPs as newly added CEPs. If we don't have local sync
	// cebManager would assume those are new CEPs and may create new CEBs for those CEPs.
	// This situation ends up having duplicate CEPs in different CEBs. Hence, we need
	// to sync existing CEBs before starting a CEP watcher.
	// On Error, return nil to caller.
	if err := getCiliumEndpointBatchesFromApiServer(cebC.clientV2a1, cebC.Manager); err != nil {
		log.WithError(err).Fatal("Failed to get CEBs from K8sAPIServer")
		return nil
	}

	return cebC
}

// reconcileCeb gets the list of CEB's to be created, updated and deleted
// from cebAggregator. It makes an attempt to reconcile above listed CEB's
// with k8s-apiserver.
// If reconciler have any issues or errors while syncing with k8s-apiserver,
// corresponding CEBs are queued back to aggregator to sync with API server
// in the next attempt.
func (c *CiliumEndpointBatchController) reconcileCeb() (bool, error) {

	var errCebCreate, errCebUpdate, errCebDelete []string
	// If the current latency cycle exceeds the cebDeleteSyncPeriod,
	// resync all CEB's, Includes Create, Update and Delete.
	if c.cebDeleteSyncTime >= c.ciliumEndpointBatchDeleteSyncPeriod {
		c.cebDeleteSyncTime = 0
		errCebCreate, errCebUpdate, errCebDelete =
			c.reconciler.reconcileWithServer(c.aggregator.getCreateUpdateAndDeleteCebNames())
	} else {
		// During normal reconcile, only CebCreate and CebUpdate are reconciled.
		// pass an empty cebDelete to reconciler.
		var cebDelete []string
		cebCreate, cebUpdate := c.aggregator.getCreateAndUpdateCebNames()
		c.cebDeleteSyncTime += c.ciliumEndpointBatchUpsertSyncPeriod
		// Reconcile only Create and Update CEB's with k8s-apiserver.
		errCebCreate, errCebUpdate, errCebDelete =
			c.reconciler.reconcileWithServer(cebCreate, cebUpdate, cebDelete)
	}

	// If local CEB's are not reconciled with k8s-apiserver,
	// queue them in aggregator to resync during next reconcile process.
	for _, cebName := range errCebCreate {
		c.aggregator.updateAggregator(cebName, CebCreate)
	}

	for _, cebName := range errCebUpdate {
		c.aggregator.updateAggregator(cebName, CebUpdate)
	}

	for _, cebName := range errCebDelete {
		c.aggregator.updateAggregator(cebName, CebDelete)
	}

	return false, nil
}

func (c *CiliumEndpointBatchController) Run(ces cache.Indexer) error {

	log.Infof("Bootstrap ceb controller")

	// Cache CiliumEndpointStore Interface locally
	c.ciliumEndpointStore = ces

	// On operator warm boot, remove stale cep entries present in CEB
	if err := c.ciliumRemoveStaleCepEntries(); err != nil {
		log.WithError(err).Error("Failed to remove stale CEP entries")
		return nil
	}

	// Reconcile current state with desired state at every
	// ciliumEndpointBatchUpsertSyncPeriod
	log.Infof("Starting CEB controller reconciler, Create/Update syncperiod: %#v Delete Sync period:%#v",
		c.ciliumEndpointBatchUpsertSyncPeriod, c.ciliumEndpointBatchDeleteSyncPeriod)

	go wait.PollInfinite(c.ciliumEndpointBatchUpsertSyncPeriod, c.reconcileCeb)
	return nil
}

// Upon warm boot[restart], Iterate over all CEPs which we got from api-server
// and compare it with CEP's packed inside CEB.
// If there is any stale CEP's present in CEBs, remove it from CEB.
func (c *CiliumEndpointBatchController) ciliumRemoveStaleCepEntries() error {
	log.Infof("Remove stale CEP entries in CEB")

	actualCepList := make(map[string]struct{})

	// List all ceps from cache
	for _, cepObj := range c.ciliumEndpointStore.List() {
		if cep, ok := cepObj.(*capi_v2.CiliumEndpoint); ok {
			actualCepList[getCepNameFromCEP(cep)] = struct{}{}
		}
	}

	// Get all ceps from local datastore
	staleCeps := c.Manager.getAllCeps()

	log.Infof("Cep count from cache(api-server): %d Cep count from local datastore: %d",
		len(c.ciliumEndpointStore.List()), len(staleCeps))

	// Remove stale CEP entries present in CEB
	for cepName, cCep := range staleCeps {
		if _, ok := actualCepList[cepName]; !ok {
			log.Debugf("Removing stale CEP entry :%s ", cepName, getCepNameFromCCEP(cCep))
			c.Manager.RemoveCepFromCache(cCep)
		}
	}

	return nil
}

// convertCeptoCoreCep converts a CiliumEndpoint to a minimal CoreCiliumEndpoint
// containing only a minimal set of entities used to
func (c *CiliumEndpointBatchController) ConvertCeptoCoreCep(cep *capi_v2.CiliumEndpoint) *capi_v2a1.CoreCiliumEndpoint {

	// Copy Networking field into core CEP
	var epNetworking *capi_v2.EndpointNetworking
	if cep.Status.Networking != nil {
		epNetworking = new(capi_v2.EndpointNetworking)
		cep.Status.Networking.DeepCopyInto(epNetworking)
	}
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
	return &capi_v2a1.CoreCiliumEndpoint{
		Name:       cep.GetName(),
		Namespace:  cep.Namespace,
		Networking: epNetworking,
		Encryption: cep.Status.Encryption,
		IdentityID: identityID,
		NamedPorts: namedPorts,
	}
}

// getCiliumEndpointBatchesFromApiServer gets existing CEBs from api-server and syncs locally in cache.
// If there is any error in syncing CEBs from api-server, returns error.
func getCiliumEndpointBatchesFromApiServer(client csv2a1.CiliumV2alpha1Interface, manager cebManager) error {
	var err error
	var cebs *capi_v2a1.CiliumEndpointBatchList

	// List all CEB's from ApiServer
	err = wait.ExponentialBackoff(apiServerBackoff, func() (bool, error) {
		var ok error
		if cebs, ok = client.CiliumEndpointBatches().List(context.Background(), meta_v1.ListOptions{}); ok == nil {
			return true, nil
		}
		log.WithError(ok).Info("Failed to get Cilium Endpoint batch list from Apiserver, retry again.")
		return false, nil
	})

	// Return Error, if we fail to get CEB list.
	if err != nil {
		return err
	}

	for _, ceb := range cebs.Items {

		cebName := ceb.GetName()

		// If CEB is already cached locally, do nothing.
		if _, ok := manager.getCebFromCache(cebName); ok == nil {
			continue
		}

		// Create new CEB locally, with the given cebName
		manager.createCeb(cebName)

		// Deep copy the ceb the one we got from API server to local datastore.
		manager.updateCebInCache(&ceb, true)

	}

	log.Debugf("Succesfully synced all CEBs locally :%s", manager.getCebCount())

	return nil
}
