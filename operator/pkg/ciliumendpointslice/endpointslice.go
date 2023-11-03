// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"time"

	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
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
	// Default CES Synctime, multiple consecutive syncs with k8s-apiserver are
	// batched and synced together after a short delay.
	DefaultCESSyncTime = 500 * time.Millisecond

	CESWriteQPSLimitMax = 50
	CESWriteQPSBurstMax = 100
)

func (c *Controller) initializeQueue() {
	if c.writeQPSLimit == 0 {
		c.writeQPSLimit = CESControllerWorkQueueQPSLimit
	} else if c.writeQPSLimit > CESWriteQPSLimitMax {
		c.writeQPSLimit = CESWriteQPSLimitMax
	}

	if c.writeQPSBurst == 0 {
		c.writeQPSBurst = CESControllerWorkQueueBurstLimit
	} else if c.writeQPSBurst > CESWriteQPSBurstMax {
		c.writeQPSBurst = CESWriteQPSBurstMax
	}

	c.logger.WithFields(logrus.Fields{
		logfields.WorkQueueQPSLimit:    c.writeQPSLimit,
		logfields.WorkQueueBurstLimit:  c.writeQPSBurst,
		logfields.WorkQueueSyncBackOff: defaultSyncBackOff,
	}).Info("CES controller workqueue configuration")

	c.queue = workqueue.NewRateLimitingQueueWithConfig(
		workqueue.NewItemExponentialFailureRateLimiter(defaultSyncBackOff, maxSyncBackOff),
		workqueue.RateLimitingQueueConfig{Name: "cilium_endpoint_slice"})
	c.queueRateLimiter = rate.NewLimiter(rate.Limit(c.writeQPSLimit), c.writeQPSBurst)
}

func (c *Controller) onEndpointUpdate(cep *cilium_api_v2.CiliumEndpoint) {
	if cep.Status.Networking == nil || cep.Status.Identity == nil || cep.GetName() == "" || cep.Namespace == "" {
		return
	}
	touchedCESs := c.manager.UpdateCEPMapping(k8s.ConvertCEPToCoreCEP(cep), cep.Namespace)
	c.enqueueCESReconciliation(touchedCESs)
}

func (c *Controller) onEndpointDelete(cep *cilium_api_v2.CiliumEndpoint) {
	touchedCES := c.manager.RemoveCEPMapping(k8s.ConvertCEPToCoreCEP(cep), cep.Namespace)
	c.enqueueCESReconciliation([]CESName{touchedCES})
}

func (c *Controller) onSliceUpdate(ces *capi_v2a1.CiliumEndpointSlice) {
	c.enqueueCESReconciliation([]CESName{NewCESName(ces.Name)})
}

func (c *Controller) onSliceDelete(ces *capi_v2a1.CiliumEndpointSlice) {
	c.enqueueCESReconciliation([]CESName{NewCESName(ces.Name)})
}

func (c *Controller) enqueueCESReconciliation(cess []CESName) {
	for _, ces := range cess {
		c.logger.WithFields(logrus.Fields{
			logfields.CESName: ces.string(),
		}).Debug("Enqueueing CES (if not empty name)")
		if ces.Name != "" {
			c.enqueuedAtLock.Lock()
			if c.enqueuedAt[ces].IsZero() {
				c.enqueuedAt[ces] = time.Now()
			}
			c.enqueuedAtLock.Unlock()
			c.queue.AddAfter(ces, DefaultCESSyncTime)
		}
	}
}

func (c *Controller) getAndResetCESProcessingDelay(ces CESName) float64 {
	c.enqueuedAtLock.Lock()
	defer c.enqueuedAtLock.Unlock()
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
func (c *Controller) Start(ctx hive.HookContext) error {
	c.logger.Info("Bootstrap ces controller")
	c.context, c.contextCancel = context.WithCancel(context.Background())
	defer utilruntime.HandleCrash()
	if c.slicingMode == cesIdentityBasedSlicing {
		c.manager = newCESManagerIdentity(c.maxCEPsInCES, c.logger)
	} else {
		c.manager = newCESManagerFcfs(c.maxCEPsInCES, c.logger)
	}
	c.reconciler = newReconciler(c.context, c.clientset.CiliumV2alpha1(), c.manager, c.logger, c.ciliumEndpoint, c.ciliumEndpointSlice, c.metrics)

	c.initializeQueue()

	if err := c.syncCESsInLocalCache(ctx); err != nil {
		return err
	}

	// Start the work pools processing CEP events only after syncing CES in local cache.
	c.wp = workerpool.New(2)
	c.wp.Submit("cilium-endpoints-updater", c.runCiliumEndpointsUpdater)
	c.wp.Submit("cilium-endpoint-slices-updater", c.runCiliumEndpointSliceUpdater)

	c.logger.Info("Starting CES controller reconciler.")
	go c.worker()

	return nil
}

func (c *Controller) Stop(ctx hive.HookContext) error {
	c.wp.Close()
	c.queue.ShutDown()
	c.contextCancel()
	return nil
}

func (c *Controller) runCiliumEndpointsUpdater(ctx context.Context) error {
	for event := range c.ciliumEndpoint.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Upsert Endpoint event")
			c.onEndpointUpdate(event.Object)
		case resource.Delete:
			c.logger.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Delete Endpoint event")
			c.onEndpointDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

func (c *Controller) runCiliumEndpointSliceUpdater(ctx context.Context) error {
	for event := range c.ciliumEndpointSlice.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.WithFields(logrus.Fields{
				logfields.CESName: event.Key.String()}).Debug("Got Upsert Endpoint Slice event")
			c.onSliceUpdate(event.Object)
		case resource.Delete:
			c.logger.WithFields(logrus.Fields{
				logfields.CESName: event.Key.String()}).Debug("Got Delete Endpoint Slice event")
			c.onSliceDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

// Sync all CESs from cesStore to manager cache.
// Note: CESs are synced locally before CES controller running and this is required.
func (c *Controller) syncCESsInLocalCache(ctx context.Context) error {
	store, err := c.ciliumEndpointSlice.Store(ctx)
	if err != nil {
		c.logger.WithError(err).Warn("Error getting CES Store")
		return err
	}
	for _, ces := range store.List() {
		cesName := c.manager.initializeMappingForCES(ces)
		for _, cep := range ces.Endpoints {
			c.manager.initializeMappingCEPtoCES(&cep, ces.Namespace, cesName)
		}
	}
	c.logger.Debug("Successfully synced all CESs locally")
	return nil
}

// worker runs a worker thread that just dequeues items, processes them, and
// marks them done.
func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) rateLimitProcessing() {
	delay := c.queueRateLimiter.Reserve().Delay()
	select {
	case <-c.context.Done():
	case <-time.After(delay):
	}
}

func (c *Controller) processNextWorkItem() bool {
	c.rateLimitProcessing()
	cKey, quit := c.queue.Get()
	if quit {
		return false
	}
	key := cKey.(CESName)
	c.logger.WithFields(logrus.Fields{
		logfields.CESName: key.string(),
	}).Debug("Processing CES")
	defer c.queue.Done(key)

	queueDelay := c.getAndResetCESProcessingDelay(key)
	err := c.reconciler.reconcileCES(key)
	c.metrics.CiliumEndpointSliceQueueDelay.Observe(queueDelay)
	if err != nil {
		c.metrics.CiliumEndpointSliceSyncTotal.WithLabelValues(LabelValueOutcomeFail).Inc()
	} else {
		c.metrics.CiliumEndpointSliceSyncTotal.WithLabelValues(LabelValueOutcomeSuccess).Inc()
	}

	c.handleErr(err, key)

	return true
}

func (c *Controller) handleErr(err error, key CESName) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	// Increment error count for sync errors
	c.metrics.CiliumEndpointSliceSyncErrors.Inc()

	if c.queue.NumRequeues(key) < maxRetries {
		c.queue.AddRateLimited(key)
		return
	}

	// Drop the CES from queue, we maxed out retries.
	c.logger.WithError(err).WithFields(logrus.Fields{
		logfields.CESName: key.string(),
	}).Error("Dropping the CES from queue, exceeded maxRetries")
	c.queue.Forget(key)
}
