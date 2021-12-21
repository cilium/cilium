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

package ciliumendpointslice

import (
	"time"

	"github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
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
	// cesNamePrefix is the prefix name added for the CiliumEndpointSlice
	// resource.
	cesNamePrefix = "ces"

	// defaultSyncBackOff is the default backoff period for cesSync calls.
	defaultSyncBackOff = 1 * time.Second
	// maxSyncBackOff is the max backoff period for cesSync calls.
	maxSyncBackOff = 100 * time.Second
	// maxRetries is the number of times a cesSync will be retried before it is
	// dropped out of the queue.
	maxRetries = 15
	// CEPs are batched into a CES, based on its Identity
	cesIdentityBasedSlicing = "cesSliceModeIdentity"
	// default qps limit value for workqueues, this only for retries.
	CESControllerWorkQueueQPSLimit = 10
	// default burst limit value for workqueues.
	CESControllerWorkQueueBurstLimit = 100
	// Delayed CES Synctime, CES's are synced with k8s-apiserver after certain delay
	// Some CES's are delayed to sync with k8s-apiserver.
	DelayedCESSyncTime = 15 * time.Second
	// Default CES Synctime, sync instantaeously with k8s-apiserver.
	DefaultCESSyncTime = 0
)

type CiliumEndpointSliceController struct {
	// Cilium kubernetes clients to access V2 and V2alpha1 resources
	clientV2   csv2.CiliumV2Interface
	clientV2a1 csv2a1.CiliumV2alpha1Interface

	// reconciler is an util used to reconcile CiliumEndpointSlice changes.
	reconciler *reconciler

	// Manager is used to create and maintain a local datastore. Manager watches for
	// cilium endpoint changes and enqueues/dequeues the cilium endpoint changes in CES.
	// It maintains the desired state of the CESs in dataStore
	Manager operations

	// ciliumEndpointStore is used to get current active CEPs in a cluster.
	ciliumEndpointStore cache.Indexer

	// workerLoopPeriod is the time between worker runs
	workerLoopPeriod time.Duration

	// workqueue is used to sync CESs with the api-server. this will rate-limit the
	// CES requests going to api-server, ensures a single CES will not be proccessed
	// multiple times concurrently, and if CES is added multiple times before it
	// can be processed, this will only be processed only once.
	queue workqueue.RateLimitingInterface

	// ciliumEndpointSliceStore is used to get current active CESs in a cluster.
	ciliumEndpointSliceStore cache.Store

	// slicingMode indicates how CEP are sliceed in a CES
	slicingMode string
}

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ces-controller")

// Derives the unique name from CoreCiliumEndpoint object.
// This unique name is used for mapping CiliumEndpoint to CiliumEndpointSlice.
// Used widely, to determine if the given CEP is mapped to any CES or not.
func GetCEPNameFromCCEP(cep *capi_v2a1.CoreCiliumEndpoint, namespace string) string {
	return namespace + "/" + cep.Name
}

// NewCESController, creates and initializes the CES controller
func NewCESController(client *k8s.K8sCiliumClient,
	maxCEPsInCES int,
	slicingMode string,
	qpsLimit float64,
	burstLimit int,
) *CiliumEndpointSliceController {
	if qpsLimit == 0 {
		qpsLimit = CESControllerWorkQueueQPSLimit
	}

	if burstLimit == 0 {
		burstLimit = CESControllerWorkQueueBurstLimit
	}

	log.WithFields(logrus.Fields{
		logfields.WorkQueueQPSLimit:    qpsLimit,
		logfields.WorkQueueBurstLimit:  burstLimit,
		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
	}).Info("CES controller workqueue configuration")

	rlQueue := workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
		// 10 qps, 100 bucket size. This is only for retry speed and its
		// only the overall factor (not per item).
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(qpsLimit), burstLimit)},
	), "cilium_endpoint_slice")

	manager := newCESManagerFcfs(rlQueue, maxCEPsInCES)
	if slicingMode == cesIdentityBasedSlicing {
		manager = newCESManagerIdentity(rlQueue, maxCEPsInCES)
	}
	cesStore := ciliumEndpointSliceInit(client.CiliumV2alpha1(), wait.NeverStop)

	// List all existing CESs from the api-server and cache it locally.
	// This sync should happen before starting CEP watcher, because CEP watcher
	// emits the existing CEPs as newly added CEPs. If we don't have local sync
	// cesManager would assume those are new CEPs and may create new CESs for those CEPs.
	// This situation ends up having duplicate CEPs in different CESs. Hence, we need
	// to sync existing CESs before starting a CEP watcher.
	syncCESsInLocalCache(cesStore, manager)
	return &CiliumEndpointSliceController{
		clientV2:                 client.CiliumV2(),
		clientV2a1:               client.CiliumV2alpha1(),
		reconciler:               newReconciler(client.CiliumV2alpha1(), manager),
		Manager:                  manager,
		queue:                    rlQueue,
		ciliumEndpointSliceStore: cesStore,
		slicingMode:              slicingMode,
		workerLoopPeriod:         1 * time.Second,
	}
}

// start the worker thread, reconciles the modified CESs with api-server
func (c *CiliumEndpointSliceController) Run(ces cache.Indexer, stopCh chan struct{}) {
	log.Info("Bootstrap ces controller")
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	// Cache CiliumEndpointStore Interface locally
	c.ciliumEndpointStore = ces

	// On operator warm boot, remove stale CEP entries present in CES
	c.removeStaleCEPEntries()

	log.WithFields(logrus.Fields{
		logfields.CESSliceMode: c.slicingMode,
	}).Info("Starting CES controller reconciler.")

	// TODO: multiple worker threads can run concurrently to reconcile with api-server
	go wait.Until(c.worker, c.workerLoopPeriod, stopCh)

	go func() {
		defer utilruntime.HandleCrash()
	}()

	<-stopCh

	return
}

// Upon warm boot[restart], Iterate over all CEPs which we got from the api-server
// and compare it with CEPs packed inside CES.
// If there are any stale CEPs present in CESs, remove them from their CES.
func (c *CiliumEndpointSliceController) removeStaleCEPEntries() {
	log.Info("Remove stale CEP entries in CES")

	// Get all CEPs from local datastore
	staleCEPs := c.Manager.getAllCEPNames()

	// Remove stale CEP entries present in CES
	for _, cepName := range staleCEPs {
		// Ignore error from below api, this is added to avoid accidental cep rmeoval from cache
		if _, exists, err := c.ciliumEndpointStore.GetByKey(cepName); err == nil && exists || err != nil {
			continue
		}
		log.WithFields(logrus.Fields{
			logfields.CEPName: cepName,
		}).Debug("Removing stale CEP entry.")
		c.Manager.RemoveCEPFromCache(cepName, DefaultCESSyncTime)
	}
	return
}

// Sync all CESs from cesStore to manager cache.
// Note: CESs are synced locally before CES controller running and this is required.
func syncCESsInLocalCache(cesStore cache.Store, manager operations) {
	for _, obj := range cesStore.List() {
		ces := obj.(*v2alpha1.CiliumEndpointSlice)
		// If CES is already cached locally, do nothing.
		if _, err := manager.getCESFromCache(ces.GetName()); err == nil {
			continue
		}

		// Create new CES locally, with the given cesName
		manager.createCES(ces.GetName())

		// Deep copy the ces, we got from api-server to local datastore.
		manager.updateCESInCache(ces, true)

	}
	log.Debug("Successfully synced all CESs locally")
	return
}

// worker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same ces
// at the same time
func (c *CiliumEndpointSliceController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *CiliumEndpointSliceController) processNextWorkItem() bool {
	cKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(cKey)

	err := c.syncCES(cKey.(string))
	c.handleErr(err, cKey)

	return true
}

func (c *CiliumEndpointSliceController) handleErr(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	// Increment error count for sync errors
	if operatorOption.Config.EnableMetrics {
		metrics.CiliumEndpointSliceSyncErrors.Inc()
	}

	if c.queue.NumRequeues(key) < maxRetries {
		c.queue.AddRateLimited(key)
		return
	}

	// Drop the CES from queue, we maxed out retries.
	log.WithError(err).WithFields(logrus.Fields{
		logfields.CESName: key,
	}).Error("Dropping the CES from queue, exceeded maxRetries")
	c.queue.Forget(key)
}

// syncCES reconciles the queued CES with api-server.
func (c *CiliumEndpointSliceController) syncCES(key string) error {
	// Update metrics
	if operatorOption.Config.EnableMetrics {
		metrics.CiliumEndpointSliceDensity.Observe(float64(c.Manager.getCEPCountInCES(key)))
		cepInsert, cepRemove := c.Manager.getCESMetricCountersAndClear(key)
		metrics.CiliumEndpointsChangeCount.WithLabelValues(metrics.LabelValueCEPInsert).Observe(float64(cepInsert))
		metrics.CiliumEndpointsChangeCount.WithLabelValues(metrics.LabelValueCEPRemove).Observe(float64(cepRemove))
		metrics.CiliumEndpointSliceQueueDelay.Observe(c.Manager.getCESQueueDelayInSeconds(key))
	}
	// Check the CES exists is in cesStore i.e. in api-server copy of CESs, if exist update or delete the CES.
	obj, exists, err := c.ciliumEndpointSliceStore.GetByKey(key)
	if err == nil && exists {
		ces := obj.(*v2alpha1.CiliumEndpointSlice)
		// Delete the CES, only if CEP count is zero in local copy of CES and api-server copy of CES,
		// else Update the CES
		if len(ces.Endpoints) == 0 && c.Manager.getCEPCountInCES(key) == 0 {
			if err := c.reconciler.reconcileCESDelete(key); err != nil {
				return err
			}
		} else {
			if err := c.reconciler.reconcileCESUpdate(key); err != nil {
				return err
			}
		}
	}

	if err == nil && !exists {
		// Create the CES with api-server
		if err := c.reconciler.reconcileCESCreate(key); err != nil {
			return err
		}
	}
	return nil
}

// Initialize and start CES watcher
// TODO Watch for CES's, make sure only CES controller Create/Update/Delete the CES not bad actors.
func ciliumEndpointSliceInit(client csv2a1.CiliumV2alpha1Interface, stopCh <-chan struct{}) cache.Store {
	cesStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	cesController := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(client.RESTClient(),
			capi_v2a1.CESPluralName, v1.NamespaceAll, fields.Everything()),
		&capi_v2a1.CiliumEndpointSlice{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
		cesStore,
	)
	go cesController.Run(stopCh)
	cache.WaitForCacheSync(stopCh, cesController.HasSynced)
	return cesStore
}
