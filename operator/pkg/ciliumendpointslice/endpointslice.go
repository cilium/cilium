// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/workerpool"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/workqueue"

	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
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
	identityMode = "identity"
	// CEPs are inserted into the largest, non-empty CiliumEndpointSlice
	fcfsMode = "fcfs"

	// Default CES Synctime, multiple consecutive syncs with k8s-apiserver are
	// batched and synced together after a short delay.
	DefaultCESSyncTime = 500 * time.Millisecond

	CESWriteQPSLimitMax = 50
	CESWriteQPSBurstMax = 100
)

func (c *Controller) initializeQueue() {
	c.logger.Info("CES controller workqueue configuration",
		logfields.WorkQueueQPSLimit, c.rateLimit.current.Limit,
		logfields.WorkQueueBurstLimit, c.rateLimit.current.Burst,
		logfields.WorkQueueSyncBackOff, defaultSyncBackOff)

	// Single rateLimiter controls the number of processed events in both queues.
	c.rateLimiter = workqueue.NewTypedItemExponentialFailureRateLimiter[CESKey](defaultSyncBackOff, maxSyncBackOff)
	c.fastQueue = workqueue.NewTypedRateLimitingQueueWithConfig(
		c.rateLimiter,
		workqueue.TypedRateLimitingQueueConfig[CESKey]{Name: "cilium_endpoint_slice"})
	c.standardQueue = workqueue.NewTypedRateLimitingQueueWithConfig(
		c.rateLimiter,
		workqueue.TypedRateLimitingQueueConfig[CESKey]{Name: "cilium_endpoint_slice"})
}

// On Pod Update, verify all the necessary fields are set.
// We recalculate the relevant fields when updating the CES instead of
// saving them here in case of any changes in value, to minimize the
// number of CES updates.
// Returns error if requires retry without pod update.
func (c *Controller) onPodUpdate(pod *slim_corev1.Pod) error {
	if pod.GetName() == "" || pod.Namespace == "" {
		return nil
	}

	if pod.Spec.HostNetwork { // no CEP for host networking pods
		return nil
	}

	_, err := GetPodEndpointNetworking(pod)
	if err != nil {
		c.logger.Debug("could not get endpointnetworking for pod",
			logfields.K8sPodName, pod.Name,
			logfields.Error, err)
		return nil
	}

	node, err := c.reconciler.getNodeNameForPod(pod)
	if err != nil {
		c.logger.Debug("could not get node name for pod",
			logfields.K8sPodName, pod.Name,
			logfields.Error, err)
		return nil
	}

	// TODO: Refactor
	cidKey, err := c.reconciler.getPodCIDKey(pod)
	if err != nil {
		c.logger.Debug("could not get labels for pod",
			logfields.K8sPodName, pod.Name,
			logfields.Error, err)
		return err
	}

	pCid, err := c.reconciler.getPodIdentity(cidKey)
	if err != nil {
		c.manager.AddPodMapping(pod, node, cidKey)
		return err
	}

	touchedCESs := c.manager.UpdatePodWithIdentity(pod, node, pCid)
	c.enqueueCESReconciliation(touchedCESs)
	return nil

	/*
		pCid, err := c.reconciler.getPodIdentity(cidKey)
		if err != nil {
			// The pod does not have a CID created for it yet. Pods will not be updated when the CID associated with
			// them is created. We preserve information about pods and their labels, so
			// that when the CID is created, the created CES can be reconciled with the apiserver.
			k8sLabels, errLabels := ciliumidentity.GetRelevantLabelsForPod(c.logger, pod, c.reconciler.namespaceStore)
			if errLabels != nil {
				c.logger.Debug("could not get labels for pod",
					logfields.K8sPodName, pod.Name,
					logfields.Error, err)
				return nil
			}
			cidKey := key.GetCIDKeyFromLabels(k8sLabels, labels.LabelSourceK8s)
			c.manager.AddPodMapping(pod, node, cidKey)
			return err
		}

		touchedCESs := c.manager.UpdatePodWithIdentity(pod, node, pCid)
		c.enqueueCESReconciliation(touchedCESs)
		return nil
	*/
}

func (c *Controller) onPodDelete(pod *slim_corev1.Pod) {
	touchedCES := c.manager.RemovePodMapping(pod)
	c.enqueueCESReconciliation(touchedCES)
}

func (c *Controller) onSliceUpdate(ces *capi_v2a1.CiliumEndpointSlice) {
	c.enqueueCESReconciliation([]CESKey{NewCESKey(ces.Name, ces.Namespace)})
}

func (c *Controller) onSliceDelete(ces *capi_v2a1.CiliumEndpointSlice) {
	c.enqueueCESReconciliation([]CESKey{NewCESKey(ces.Name, ces.Namespace)})
}

func (c *Controller) onNodeUpdate(node *capi_v2.CiliumNode) {
	touchedCESs := c.manager.UpdateNodeMapping(node)
	c.enqueueCESReconciliation(touchedCESs)
}

func (c *Controller) onNodeDelete(node *capi_v2.CiliumNode) {
	touchedCESs := c.manager.RemoveNodeMapping(node)
	c.enqueueCESReconciliation(touchedCESs)
}

func (c *Controller) onIdentityUpdate(cid *capi_v2.CiliumIdentity) {
	touchedCESs := c.manager.UpdateIdentityMapping(cid)
	c.enqueueCESReconciliation(touchedCESs)
}

func (c *Controller) onIdentityDelete(cid *capi_v2.CiliumIdentity) {
	touchedCESs := c.manager.RemoveIdentityMapping(cid)
	c.enqueueCESReconciliation(touchedCESs)
}

func (c *Controller) addToQueue(ces CESKey) {
	c.priorityNamespacesLock.RLock()
	_, exists := c.priorityNamespaces[ces.Namespace]
	c.priorityNamespacesLock.RUnlock()
	time.AfterFunc(c.syncDelay, func() {
		c.cond.L.Lock()
		defer c.cond.L.Unlock()
		if exists {
			c.fastQueue.Add(ces)
		} else {
			c.standardQueue.Add(ces)
		}
		c.cond.Signal()
	})
}

func (c *Controller) enqueueCESReconciliation(cess []CESKey) {
	for _, ces := range cess {
		c.logger.Debug("Enqueueing CES (if not empty name)", logfields.CESName, ces.string())
		if ces.Name != "" {
			c.enqueuedAtLock.Lock()
			if c.enqueuedAt[ces].IsZero() {
				c.enqueuedAt[ces] = time.Now()
			}
			c.enqueuedAtLock.Unlock()
			c.addToQueue(ces)
		}
	}
}

func (c *Controller) getAndResetCESProcessingDelay(ces CESKey) float64 {
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
func (c *Controller) Start(ctx cell.HookContext) error {
	// Processing CES/Pod events:
	// CES or Pod event is retrieved and checked whether it is from a priority namespace
	// Event is added to the fast queue if the namespace was priority and to the standard queue otherwise

	// Processing queues:
	// The controller checks if the fast queue and standard queue are empty
	// If yes, it waits on signal
	// if no, it checks if fast queue is empty
	// If no, it takes element from the fast queue. Otherwise it takes element from the standard queue.
	// CES from the queue is reconciled with the k8s api-server
	// if error appears while reconciling and maximum number of retries for this element has not been reached, it is added to the appropriate queue.
	// if the error has not appeared or the maximum number of retries has been reached, the element is forgotten.

	c.logger.Info("Bootstrap ces controller")
	c.context, c.contextCancel = context.WithCancel(context.Background())
	defer utilruntime.HandleCrash()

	c.manager = newCESManager(c.maxCEPsInCES, c.logger)

	c.reconciler = newReconciler(c.context, c.clientset.CiliumV2alpha1(), c.manager, c.logger, c.pods, c.ciliumEndpointSlice, c.ciliumNodes, c.namespace, c.ciliumIdentity, c.metrics)

	c.initializeQueue()

	if err := c.syncCESsInLocalCache(ctx); err != nil {
		return err
	}

	c.Job.Add(
		job.OneShot("proc-ns-events", func(ctx context.Context, health cell.Health) error {
			return c.processNamespaceEvents(ctx)
		}),
	)
	// Start the work pools processing CEP events only after syncing CES in local cache.
	c.wp = workerpool.New(4)
	c.wp.Submit("cilium-pods-updater", c.runCiliumPodsUpdater)
	c.wp.Submit("cilium-endpoint-slices-updater", c.runCiliumEndpointSliceUpdater)
	c.wp.Submit("cilium-nodes-updater", c.runCiliumNodesUpdater)
	c.wp.Submit("cilium-identities-updater", c.runCiliumIdentitiesUpdater)

	c.logger.Info("Starting CES controller reconciler.")
	c.Job.Add(
		job.OneShot("proc-queues", func(ctx context.Context, health cell.Health) error {
			c.worker()
			return nil
		}),
	)

	return nil
}

func (c *Controller) Stop(ctx cell.HookContext) error {
	c.wp.Close()
	c.fastQueue.ShutDown()
	c.standardQueue.ShutDown()
	c.contextCancel()
	return nil
}

func (c *Controller) runCiliumPodsUpdater(ctx context.Context) error {
	for event := range c.pods.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert Pod event", logfields.K8sPodName, event.Key)
			err := c.onPodUpdate(event.Object)
			event.Done(err)
		case resource.Delete:
			c.logger.Debug("Got Delete Pod event", logfields.K8sPodName, event.Key)
			c.onPodDelete(event.Object)
			event.Done(nil)
		default:
			event.Done(nil)
		}
	}
	return nil
}

func (c *Controller) runCiliumEndpointSliceUpdater(ctx context.Context) error {
	for event := range c.ciliumEndpointSlice.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert Endpoint Slice event", logfields.CESName, event.Key)
			c.onSliceUpdate(event.Object)
		case resource.Delete:
			c.logger.Debug("Got Delete Endpoint Slice event", logfields.CESName, event.Key)
			c.onSliceDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

func (c *Controller) runCiliumNodesUpdater(ctx context.Context) error {
	ciliumNodesStore, err := c.ciliumNodes.Store(ctx)
	if err != nil {
		c.logger.Warn("Couldn't get CiliumNodes store", logfields.Error, err)
		return err
	}

	for event := range c.ciliumNodes.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert CiliumNode event", logfields.NodeName, event.Key)
			c.onNodeUpdate(event.Object)
		case resource.Delete:
			c.logger.Debug("Got Delete CiliumNode event", logfields.NodeName, event.Key)
			c.onNodeDelete(event.Object)
		}
		event.Done(nil)

		// Update dynamic rate limiter
		totalNodes := len(ciliumNodesStore.List())
		if c.rateLimit.updateRateLimiterWithNodes(totalNodes) {
			c.logger.Info("Updated CES controller workqueue configuration",
				logfields.WorkQueueQPSLimit, c.rateLimit.current.Limit,
				logfields.WorkQueueBurstLimit, c.rateLimit.current.Burst)
		}
	}
	return nil
}

func (c *Controller) runCiliumIdentitiesUpdater(ctx context.Context) error {
	for event := range c.ciliumIdentity.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert CiliumIdentity event", logfields.CIDName, event.Key)
			c.onIdentityUpdate(event.Object)
		case resource.Delete:
			c.logger.Debug("Got Delete CiliumNode event", logfields.CIDName, event.Key)
			c.onIdentityDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

// Sync all CESs from cesStore to manager cache.
// Note: CESs are synced locally before CES controller running and this is required.
// TODO(jshr-w): Does anything here need to be retried?
func (c *Controller) syncCESsInLocalCache(ctx context.Context) error {
	cesStore, err := c.ciliumEndpointSlice.Store(ctx)
	if err != nil {
		c.logger.Warn("Error getting CES Store", logfields.Error, err)
		return err
	}

	cnodeStore, err := c.ciliumNodes.Store(ctx)
	if err != nil {
		c.logger.Warn("Error getting CiliumNode Store", logfields.Error, err)
		return err
	}

	podStore, err := c.pods.Store(ctx)
	if err != nil {
		c.logger.Warn("Error getting Pod Store", logfields.Error, err)
		return err
	}

	cidStore, err := c.ciliumIdentity.Store(ctx)
	if err != nil {
		c.logger.Warn("Error getting CID Store", logfields.Error, err)
		return err
	}

	for _, cnode := range cnodeStore.List() {
		c.manager.UpdateNodeMapping(cnode)
	}

	cepToCes := make(map[string]CESName)
	for _, ces := range cesStore.List() {
		cesName := c.manager.initializeMappingForCES(ces)
		for _, cep := range ces.Endpoints {
			cepToCes[cep.Name] = cesName
		}
	}

	for _, cid := range cidStore.List() {
		c.manager.UpdateIdentityMapping(cid)
	}

	for _, pod := range podStore.List() {
		// We are syncing the cesStore with the manager cache, therefore
		// we only sync pods that are already mapped to a CES.
		if cesName, ok := cepToCes[pod.Name]; ok {
			node, err := c.reconciler.getNodeNameForPod(pod)
			if err != nil {
				continue
			}

			cidKey, err := c.reconciler.getPodCIDKey(pod)
			if err != nil {
				continue
			}

			podCid, err := c.reconciler.getPodIdentity(cidKey)
			if err != nil {
				continue
			}

			cidName, gidLabels := cidToGidLabels(podCid)
			c.manager.initializeMappingPodToNode(pod, pod.Namespace, node, cesName, cidName, gidLabels)
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
	delay := c.rateLimit.getDelay()
	select {
	case <-c.context.Done():
	case <-time.After(delay):
	}
}

func (c *Controller) getQueue() workqueue.TypedRateLimitingInterface[CESKey] {
	c.cond.L.Lock()
	defer c.cond.L.Unlock()

	if c.fastQueue.Len() == 0 && c.standardQueue.Len() == 0 {
		c.cond.Wait()
	}

	if c.fastQueue.Len() == 0 {
		return c.standardQueue
	} else {
		return c.fastQueue
	}
}

func (c *Controller) processNextWorkItem() bool {
	c.rateLimitProcessing()
	queue := c.getQueue()
	key, quit := queue.Get()
	if quit {
		return false
	}
	defer queue.Done(key)

	c.logger.Debug("Processing CES", logfields.CESName, key.string())

	queueDelay := c.getAndResetCESProcessingDelay(key)
	err := c.reconciler.reconcileCES(CESName(key.Name))
	if queue == c.fastQueue {
		c.metrics.CiliumEndpointSliceQueueDelay.WithLabelValues(LabelQueueFast).Observe(queueDelay)
	} else {
		c.metrics.CiliumEndpointSliceQueueDelay.WithLabelValues(LabelQueueStandard).Observe(queueDelay)
	}
	if err != nil {
		c.metrics.CiliumEndpointSliceSyncTotal.WithLabelValues(LabelValueOutcomeFail).Inc()
	} else {
		c.metrics.CiliumEndpointSliceSyncTotal.WithLabelValues(LabelValueOutcomeSuccess).Inc()
	}

	c.handleErr(queue, err, key)

	return true
}

func (c *Controller) handleErr(queue workqueue.TypedRateLimitingInterface[CESKey], err error, key CESKey) {
	if err == nil {
		queue.Forget(key)
		return
	}

	if queue.NumRequeues(key) < maxRetries {
		time.AfterFunc(c.rateLimiter.When(key), func() {
			c.cond.L.Lock()
			defer c.cond.L.Unlock()
			queue.Add(key)
			c.cond.Signal()
		})
		return
	}

	// Drop the CES from queue, we maxed out retries.
	c.logger.Error("Dropping the CES from queue, exceeded maxRetries",
		logfields.CESName, key.string(),
		logfields.Error, err)
	queue.Forget(key)
}
