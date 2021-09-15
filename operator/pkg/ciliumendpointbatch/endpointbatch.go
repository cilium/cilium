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
	"time"

	"github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	csv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	csv2a1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const (
	// cebNamePrefix is the prefix name added for the CiliumEndpointBatch
	// resource.
	cebNamePrefix = "ceb"

	// defaultSyncBackOff is the default backoff period for cebSync calls.
	defaultSyncBackOff = 1 * time.Second
	// maxSyncBackOff is the max backoff period for cebSync calls.
	maxSyncBackOff = 100 * time.Second
	// maxRetries is the number of times a cebSync will be retried before it is
	// dropped out of the queue.
	maxRetries = 15
	// CEPs are batched into a CEB, based on its Identity
	cebIdentityBasedBatching = "cebBatchModeIdentity"
)

type CiliumEndpointBatchController struct {
	// Cilium kubernetes clients to access V2 and V2alpha1 resources
	clientV2   csv2.CiliumV2Interface
	clientV2a1 csv2a1.CiliumV2alpha1Interface

	// reconciler is an util used to reconcile CiliumEndpointBatch changes.
	reconciler *reconciler

	// Manager is used to create and maintain a local datastore. Manager watches for
	// cilium endpoint changes and enqueues/dequeues the cilium endpoint changes in CEB.
	// It maintains the desired state of the CEBs in dataStore
	Manager cebManager

	// ciliumEndpointStore is used to get current active CEPs in a cluster.
	ciliumEndpointStore cache.Indexer

	// workerLoopPeriod is the time between worker runs
	workerLoopPeriod time.Duration

	// workqueue is used to sync CEBs with the api-server. this will rate-limit the
	// CEB requests going to api-server, ensures a single CEB will not be proccessed
	// multiple times concurrently, and if CEB is added multiple times before it
	// can be processed, this will only be processed only once.
	queue workqueue.RateLimitingInterface

	// ciliumEndpointBatchStore is used to get current active CEBs in a cluster.
	ciliumEndpointBatchStore cache.Store

	// batchingMode indicates how CEP are batched in a CEB
	batchingMode string
}

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ceb-controller")

// Derives the unique name from CoreCiliumEndpoint object.
// This unique name is used for mapping CiliumEndpoint to CiliumEndpointBatch.
// Used widely, to determine if the given CEP is mapped to any CEB or not.
func GetCepNameFromCCEP(cep *capi_v2a1.CoreCiliumEndpoint) string {
	return cep.Namespace + "/" + cep.Name
}

// NewCebController, creates and initializes the CEB controller
func NewCebController(client *k8s.K8sCiliumClient,
	maxCepsInCeb int,
	batchingMode string,
	qpsLimit float64,
	burstLimit int,
) *CiliumEndpointBatchController {

	rlQueue := workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
		// 5 qps, 10 bucket size. This is only for retry speed and its
		// only the overall factor (not per item).
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(qpsLimit), burstLimit)},
	), "cilium_endpoint_batch")

	manager := newCebManagerFcfs(rlQueue, maxCepsInCeb)
	if batchingMode == cebIdentityBasedBatching {
		manager = newCebManagerIdentity(rlQueue, maxCepsInCeb)
	}
	cebStore := ciliumEndpointBatchInit(client.CiliumV2alpha1(), wait.NeverStop)

	// List all existing CEBs from the api-server and cache it locally.
	// This sync should happen before starting CEP watcher, because CEP watcher
	// emits the existing CEPs as newly added CEPs. If we don't have local sync
	// cebManager would assume those are new CEPs and may create new CEBs for those CEPs.
	// This situation ends up having duplicate CEPs in different CEBs. Hence, we need
	// to sync existing CEBs before starting a CEP watcher.
	syncCebsInLocalCache(cebStore, manager)
	return &CiliumEndpointBatchController{
		clientV2:                 client.CiliumV2(),
		clientV2a1:               client.CiliumV2alpha1(),
		reconciler:               newReconciler(client.CiliumV2alpha1(), manager),
		Manager:                  manager,
		queue:                    rlQueue,
		ciliumEndpointBatchStore: cebStore,
		batchingMode:             batchingMode,
		workerLoopPeriod:         1 * time.Second,
	}
}

// start the worker thread, reconciles the modified CEBs with api-server
func (c *CiliumEndpointBatchController) Run(ces cache.Indexer, stopCh chan struct{}) {

	log.Info("Bootstrap ceb controller")
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	// Cache CiliumEndpointStore Interface locally
	c.ciliumEndpointStore = ces

	// On operator warm boot, remove stale cep entries present in CEB
	c.removeStaleCepEntries()

	log.WithFields(logrus.Fields{
		"Batching mode": c.batchingMode,
	}).Info("Starting CEB controller reconciler.")

	// TODO: multiple worker threads can run concurrently to reconcile with api-server
	go wait.Until(c.worker, c.workerLoopPeriod, stopCh)

	go func() {
		defer utilruntime.HandleCrash()
	}()

	<-stopCh

	return
}

// Upon warm boot[restart], Iterate over all CEPs which we got from the api-server
// and compare it with CEPs packed inside CEB.
// If there are any stale CEPs present in CEBs, remove them from their CEB.
func (c *CiliumEndpointBatchController) removeStaleCepEntries() {
	log.Info("Remove stale CEP entries in CEB")

	// Get all ceps from local datastore
	staleCeps := c.Manager.getAllCepNames()

	// Remove stale CEP entries present in CEB
	for _, cepName := range staleCeps {
		// Ignore error from below api, this is added to avoid accidental cep rmeoval from cache
		if _, exists, err := c.ciliumEndpointStore.GetByKey(cepName); err == nil && exists || err != nil {
			continue
		}
		log.WithFields(logrus.Fields{
			"cep-name": cepName,
		}).Debug("Removing stale CEP entry.")
		c.Manager.RemoveCepFromCache(cepName)
	}
	return
}

// Sync all cebs from cebStore to manager cache.
// Note: CEBs are synced locally before CEB controller running and this is required.
func syncCebsInLocalCache(cebStore cache.Store, manager cebManager) {

	for _, obj := range cebStore.List() {
		ceb := obj.(*v2alpha1.CiliumEndpointBatch)
		// If CEB is already cached locally, do nothing.
		if _, err := manager.getCebFromCache(ceb.GetName()); err == nil {
			continue
		}

		// Create new CEB locally, with the given cebName
		manager.createCeb(ceb.GetName())

		// Deep copy the ceb, we got from api-server to local datastore.
		manager.updateCebInCache(ceb, true)

	}
	log.Debug("Successfully synced all CEBs locally")
	return
}

// worker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same ceb
// at the same time
func (c *CiliumEndpointBatchController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *CiliumEndpointBatchController) processNextWorkItem() bool {
	cKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(cKey)

	err := c.syncCeb(cKey.(string))
	c.handleErr(err, cKey)

	return true
}

func (c *CiliumEndpointBatchController) handleErr(err error, key interface{}) {

	if err == nil {
		c.queue.Forget(key)
		return
	}

	// Increment error count for sync errors
	metrics.CiliumEndpointBatchSyncErrors.WithLabelValues().Inc()
	if c.queue.NumRequeues(key) < maxRetries {
		c.queue.AddRateLimited(key)
		return
	}

	// Drop the CEB from queue, we maxed out retries.
	log.WithError(err).WithFields(logrus.Fields{
		"ceb-name": key,
	}).Error("Dropping the CEB from queue, exceeded maxRetries")
	c.queue.Forget(key)
}

// syncCeb reconciles the queued CEB with api-server.
func (c *CiliumEndpointBatchController) syncCeb(key string) error {

	// Update metrics
	metrics.CiliumEndpointBatchDensity.WithLabelValues().Observe(float64(c.Manager.getCepCountInCeb(key)))
	cepInsert, cepRemove := c.Manager.getCebMetricCountersAndClear(key)
	metrics.CiliumEndpointsChangeCount.WithLabelValues(metrics.LabelValueCEPInsert).Observe(float64(cepInsert))
	metrics.CiliumEndpointsChangeCount.WithLabelValues(metrics.LabelValueCEPRemove).Observe(float64(cepRemove))
	metrics.CiliumEndpointBatchQueueDelay.WithLabelValues().Observe(c.Manager.getCEBQueueDelayInSeconds(key))

	// Check the CEB exists is in cebStore i.e. in api-server copy of CEBs, if exist update or delete the CEB.
	obj, exists, err := c.ciliumEndpointBatchStore.GetByKey(key)
	if err == nil && exists {
		ceb := obj.(*v2alpha1.CiliumEndpointBatch)
		// Delete the CEB, only if CEP count is zero in local copy of CEB and api-server copy of CEB,
		// else Update the CEB
		if len(ceb.Endpoints) == 0 && c.Manager.getCepCountInCeb(key) == 0 {
			if err := c.reconciler.reconcileCebDelete(key); err != nil {
				return err
			}
		} else {
			if err := c.reconciler.reconcileCebUpdate(key); err != nil {
				return err
			}
		}
	}

	if err == nil && !exists {
		// Create the CEB with api-server
		if err := c.reconciler.reconcileCebCreate(key); err != nil {
			return err
		}
	}
	return nil
}

// Initialize and start CEB watcher
// TODO Watch for CEB's, make sure only CEB controller Create/Update/Delete the CEB not bad actors.
func ciliumEndpointBatchInit(client csv2a1.CiliumV2alpha1Interface, stopCh <-chan struct{}) cache.Store {
	cebStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	cebController := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(client.RESTClient(),
			capi_v2a1.CEBPluralName, v1.NamespaceAll, fields.Everything()),
		&capi_v2a1.CiliumEndpointBatch{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
		cebStore,
	)
	go cebController.Run(stopCh)
	cache.WaitForCacheSync(stopCh, cebController.HasSynced)
	return cebStore
}
