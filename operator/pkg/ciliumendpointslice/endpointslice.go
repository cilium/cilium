// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"strconv"
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
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	csv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	csv2a1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type eventType int

const (
	updateEvent eventType = iota
	deleteEvent
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

var (
	ceSliceStore cache.Store
)

type EndpointEvent struct {
	event eventType
	cep   *cilium_api_v2.CiliumEndpoint
}

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

	// workerLoopPeriod is the time between worker runs
	workerLoopPeriod time.Duration

	// workqueue is used to sync CESs with the api-server. this will rate-limit the
	// CES requests going to api-server, ensures a single CES will not be proccessed
	// multiple times concurrently, and if CES is added multiple times before it
	// can be processed, this will only be processed only once.
	queue workqueue.RateLimitingInterface

	// slicingMode indicates how CEP are sliceed in a CES
	slicingMode string

	enqueuedAt map[string]time.Time

	preInitEnqueuedEndpointsEvents []EndpointEvent

	endpointsMappingInitialized bool
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
	rlQueue := initializeQueue(qpsLimit, burstLimit)

	manager := newCESManagerFcfs(maxCEPsInCES)
	if slicingMode == cesIdentityBasedSlicing {
		manager = newCESManagerIdentity(maxCEPsInCES)
	}

	controller := &CiliumEndpointSliceController{
		clientV2:                       clientset.CiliumV2(),
		clientV2a1:                     clientset.CiliumV2alpha1(),
		reconciler:                     newReconciler(clientset.CiliumV2alpha1(), manager),
		Manager:                        manager,
		queue:                          rlQueue,
		slicingMode:                    slicingMode,
		workerLoopPeriod:               1 * time.Second,
		enqueuedAt:                     make(map[string]time.Time),
		preInitEnqueuedEndpointsEvents: make([]EndpointEvent, 0),
		endpointsMappingInitialized:    false,
	}
	cesStore := ciliumEndpointSliceInit(controller, clientset.CiliumV2alpha1(), ctx, wg)
	ceSliceStore = cesStore
	return controller
}

func ciliumEndpointSliceInit(contorller *CiliumEndpointSliceController, client csv2a1.CiliumV2alpha1Interface, ctx context.Context, wg *sync.WaitGroup) cache.Store {
	cesStore, cesController := informer.NewInformer(
		utils.ListerWatcherFromTyped[*capi_v2a1.CiliumEndpointSliceList](
			client.CiliumEndpointSlices()),
		&capi_v2a1.CiliumEndpointSlice{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if ces := objToCES(obj); ces != nil {
					contorller.onSliceUpdate(ces)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldCES := objToCES(oldObj); oldCES != nil {
					if newCES := objToCES(newObj); newCES != nil {
						if oldCES.DeepEqual(newCES) {
							return
						}
						contorller.onSliceUpdate(newCES)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				if ces := objToCES(obj); ces != nil {
					contorller.onSliceDelete(ces)
				}
			},
		},
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

func objToCES(obj interface{}) *capi_v2a1.CiliumEndpointSlice {
	switch concreteObj := obj.(type) {
	case *capi_v2a1.CiliumEndpointSlice:
		return concreteObj
	case cache.DeletedFinalStateUnknown:
		ciliumEndpoint, ok := concreteObj.Obj.(*capi_v2a1.CiliumEndpointSlice)
		if !ok {
			log.WithField(logfields.Object, logfields.Repr(concreteObj.Obj)).
				Warn("Ignoring invalid v2alpha1 CiliumEndpointSlice")
			return nil
		}
		return ciliumEndpoint
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid v2alpha1 CiliumEndpoint")
	return nil
}

func initializeQueue(qpsLimit float64, burstLimit int) workqueue.RateLimitingInterface {
	if qpsLimit == 0 {
		qpsLimit = CESControllerWorkQueueQPSLimit
	} else if qpsLimit > operatorOption.CESWriteQPSLimitMax {
		qpsLimit = operatorOption.CESWriteQPSLimitMax
	}

	if burstLimit == 0 {
		burstLimit = CESControllerWorkQueueBurstLimit
	} else if burstLimit > operatorOption.CESWriteQPSBurstMax {
		burstLimit = operatorOption.CESWriteQPSBurstMax
	}

	log.WithFields(logrus.Fields{
		logfields.WorkQueueQPSLimit:    qpsLimit,
		logfields.WorkQueueBurstLimit:  burstLimit,
		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
	}).Info("CES controller workqueue configuration")

	return workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
		// 10 qps, 100 bucket size. This is only for retry speed and its
		// only the overall factor (not per item).
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(qpsLimit), burstLimit)},
	), "cilium_endpoint_slice")
}

func (c *CiliumEndpointSliceController) OnEndpointUpdate(cep *cilium_api_v2.CiliumEndpoint) {
	if cep.Status.Networking == nil || cep.Status.Identity == nil || cep.GetName() == "" || cep.Namespace == "" {
		return
	}
	if c.endpointsMappingInitialized {
		touchedCESs := c.Manager.UpdateCEPMapping(k8s.ConvertCEPToCoreCEP(cep), cep.Namespace)
		c.enqueueCESReconciliation(touchedCESs)
	} else {
		c.preInitEnqueuedEndpointsEvents = append(c.preInitEnqueuedEndpointsEvents, EndpointEvent{event: updateEvent, cep: cep})
	}
}

func (c *CiliumEndpointSliceController) OnEndpointDelete(cep *cilium_api_v2.CiliumEndpoint) {
	if c.endpointsMappingInitialized {
		touchedCES := c.Manager.RemoveCEPMapping(k8s.ConvertCEPToCoreCEP(cep), cep.Namespace)
		c.enqueueCESReconciliation([]CESName{touchedCES})
	} else {
		c.preInitEnqueuedEndpointsEvents = append(c.preInitEnqueuedEndpointsEvents, EndpointEvent{event: deleteEvent, cep: cep})
	}
}

func (c *CiliumEndpointSliceController) onSliceUpdate(ces *capi_v2a1.CiliumEndpointSlice) {
	c.enqueueCESReconciliation([]CESName{CESName(ces.Name)})
}

func (c *CiliumEndpointSliceController) onSliceDelete(ces *capi_v2a1.CiliumEndpointSlice) {
	c.enqueueCESReconciliation([]CESName{CESName(ces.Name)})
}

func (c *CiliumEndpointSliceController) enqueueCESReconciliation(cess []CESName) {
	for _, ces := range cess {
		log.WithFields(logrus.Fields{
			logfields.CESName: ces,
		}).Debug("Enquing CES (if not empty name")
		if ces != "" {
			if c.enqueuedAt[string(ces)].IsZero() {
				c.enqueuedAt[string(ces)] = time.Now()
			}
			c.queue.AddAfter(string(ces), DefaultCESSyncTime)
		}
	}
}

func (c *CiliumEndpointSliceController) getAndResetCESProcessingDelay(ces string) float64 {
	enqueued, exists := c.enqueuedAt[ces]
	if !exists {
		return 0
	}
	if !enqueued.IsZero() {
		delay := time.Since(enqueued)
		c.enqueuedAt[ces] = time.Time{}
		return delay.Seconds()
	}
	return 0
}

// start the worker thread, reconciles the modified CESs with api-server
func (c *CiliumEndpointSliceController) Run(ciliumEndpointStore cache.Indexer, stopCh <-chan struct{}) {
	log.Info("Bootstrap ces controller")
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	// List all existing CESs from the api-server and cache it locally.
	// This sync should happen before starting CEP watcher, because CEP watcher
	// emits the existing CEPs as newly added CEPs. If we don't have local sync
	// cesManager would assume those are new CEPs and may create new CESs for those CEPs.
	// This situation ends up having duplicate CEPs in different CESs. Hence, we need
	// to sync existing CESs before starting a CEP watcher.
	c.syncCESsInLocalCache()
	c.processEnqueuedPreInitEndpoints()
	c.reconciler.ciliumEndpointStore = ciliumEndpointStore

	log.WithFields(logrus.Fields{
		logfields.CESSliceMode: c.slicingMode,
	}).Info("Starting CES controller reconciler.")

	// TODO: multiple worker threads can run concurrently to reconcile with api-server
	go wait.Until(c.worker, c.workerLoopPeriod, stopCh)

	go func() {
		defer utilruntime.HandleCrash()
	}()

	<-stopCh
}

// Sync all CESs from cesStore to manager cache.
// Note: CESs are synced locally before CES controller running and this is required.
func (c *CiliumEndpointSliceController) syncCESsInLocalCache() {
	for _, obj := range ceSliceStore.List() {
		ces := obj.(*capi_v2a1.CiliumEndpointSlice)
		cesName := c.Manager.initializeMappingForCES(ces)
		for _, cep := range ces.Endpoints {
			c.Manager.initializeMappingCEPtoCES(&cep, ces.Namespace, cesName)
		}
	}
	c.endpointsMappingInitialized = true
	log.Debug("Successfully synced all CESs locally")
}

func (c *CiliumEndpointSliceController) processEnqueuedPreInitEndpoints() {
	for _, e := range c.preInitEnqueuedEndpointsEvents {
		if e.event == updateEvent {
			c.OnEndpointUpdate(e.cep)
		} else if e.event == deleteEvent {
			c.OnEndpointDelete(e.cep)
		} else {
			log.Warnf("Processing pre init event of unknown type %d", e.event)
		}
	}
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

	queueDelay := c.getAndResetCESProcessingDelay(cKey.(string))
	err := c.reconciler.reconcileCES(cKey.(string))
	if operatorOption.Config.EnableMetrics {
		metrics.CiliumEndpointSliceQueueDelay.Observe(queueDelay)
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

// UsedIdentitiesInCESs returns all Identities that are used in CESs.
func UsedIdentitiesInCESs() map[string]bool {
	return usedIdentitiesInCESs(ceSliceStore)
}

// usedIdentitiesInCESs returns all Identities that are used in CESs in the
// specified store.
func usedIdentitiesInCESs(cesStore cache.Store) map[string]bool {
	usedIdentities := make(map[string]bool)
	if cesStore == nil {
		return usedIdentities
	}

	cesObjList := cesStore.List()
	for _, cesObj := range cesObjList {
		ces, ok := cesObj.(*capi_v2a1.CiliumEndpointSlice)
		if !ok {
			continue
		}

		for _, cep := range ces.Endpoints {
			id := strconv.FormatInt(cep.IdentityID, 10)
			usedIdentities[id] = true
		}
	}

	return usedIdentities
}
