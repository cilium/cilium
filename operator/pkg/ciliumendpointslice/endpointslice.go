// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	csv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	csv2a1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
	// Default CES Synctime, multiple consecutive syncs with k8s-apiserver are
	// batched and synced together after a short delay.
	DefaultCESSyncTime = 500 * time.Millisecond
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
func NewCESController(
	ctx context.Context,
	wg *sync.WaitGroup,
	clientset k8sClient.Clientset,
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
	cesStore := ciliumEndpointSliceInit(clientset.CiliumV2alpha1(), ctx, wg)

	// List all existing CESs from the api-server and cache it locally.
	// This sync should happen before starting CEP watcher, because CEP watcher
	// emits the existing CEPs as newly added CEPs. If we don't have local sync
	// cesManager would assume those are new CEPs and may create new CESs for those CEPs.
	// This situation ends up having duplicate CEPs in different CESs. Hence, we need
	// to sync existing CESs before starting a CEP watcher.
	syncCESsInLocalCache(cesStore, manager)
	return &CiliumEndpointSliceController{
		clientV2:                 clientset.CiliumV2(),
		clientV2a1:               clientset.CiliumV2alpha1(),
		reconciler:               newReconciler(clientset.CiliumV2alpha1(), manager),
		Manager:                  manager,
		queue:                    rlQueue,
		ciliumEndpointSliceStore: cesStore,
		slicingMode:              slicingMode,
		workerLoopPeriod:         1 * time.Second,
	}
}

// start the worker thread, reconciles the modified CESs with api-server
func (c *CiliumEndpointSliceController) Run(ces cache.Indexer, stopCh <-chan struct{}) {
	log.Info("Bootstrap ces controller")
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	// Cache CiliumEndpointStore Interface locally
	c.ciliumEndpointStore = ces

	// On operator warm boot, remove stale CEP entries present in CES
	c.removeStaleAndDuplicatedCEPEntries()

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
// If there are any duplicated CEPs present in CESs, remove all but one trying
// to keep the CEP with matching identity if it's present.
func (c *CiliumEndpointSliceController) removeStaleAndDuplicatedCEPEntries() {
	log.Info("Remove stale and duplicated CEP entries in CES")

	type cepMapping struct {
		identity int64
		cesName  string
	}

	cepsMapping := make(map[string][]cepMapping)

	// Get all CEPs from local datastore
	// Map CEP Names to list of whole structure + CES Name
	for _, ces := range c.Manager.getAllCESs() {
		for _, cep := range ces.getAllCEPs() {
			cepName := ces.getCEPNameFromCCEP(&cep)
			cepsMapping[cepName] = append(cepsMapping[cepName], cepMapping{identity: cep.IdentityID, cesName: ces.getCESName()})
		}
	}

	for cepName, mappings := range cepsMapping {
		storeCep, exists, err := c.ciliumEndpointStore.GetByKey(cepName)
		// Ignore error from below api, this is added to avoid accidental cep rmeoval from cache
		if err != nil {
			continue
		}
		if !exists {
			// Remove stale CEP entries present in CES
			for _, mapping := range mappings {
				log.WithFields(logrus.Fields{
					logfields.CEPName: cepName,
				}).Debug("Removing stale CEP entry.")
				c.Manager.removeCEPFromCES(cepName, mapping.cesName, DefaultCESSyncTime, 0, false)
			}
		} else if len(mappings) > 1 {
			// Remove duplicated CEP entries present in CES
			found := false
			cep := storeCep.(*cilium_api_v2.CiliumEndpoint)
			// Skip first element for now
			for _, mapping := range mappings[1:] {
				if !found && mapping.identity == cep.Status.Identity.ID {
					// Don't remove the first element for which identity matches
					found = true
					// All others elements will be removed so update mapping to make sure
					// it points to the element that was kept
					c.Manager.updateCEPToCESMapping(cepName, mapping.cesName)
					continue
				}
				c.Manager.removeCEPFromCES(cepName, mapping.cesName, DefaultCESSyncTime, mapping.identity, true)
			}
			if found {
				// Remove first element if element with matching identity was found
				c.Manager.removeCEPFromCES(cepName, mappings[0].cesName, DefaultCESSyncTime, mappings[0].identity, true)
			} else {
				// All others elements were removed so update mapping to make sure
				// it points to the only element left
				c.Manager.updateCEPToCESMapping(cepName, mappings[0].cesName)
			}
		}
	}
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
	if operatorOption.Config.EnableMetrics {
		if err != nil {
			metrics.CiliumEndpointSliceSyncTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		} else {
			metrics.CiliumEndpointSliceSyncTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
		}
	}

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
func ciliumEndpointSliceInit(client csv2a1.CiliumV2alpha1Interface, ctx context.Context, wg *sync.WaitGroup) cache.Store {
	cesStore, cesController := informer.NewInformer(
		utils.ListerWatcherFromTyped[*capi_v2a1.CiliumEndpointSliceList](
			client.CiliumEndpointSlices()),
		&capi_v2a1.CiliumEndpointSlice{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		cesController.Run(ctx.Done())
	}()
	cache.WaitForCacheSync(ctx.Done(), cesController.HasSynced)
	return cesStore
}
