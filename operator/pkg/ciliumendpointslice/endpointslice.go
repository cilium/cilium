// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/workerpool"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
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

	// Default CES Synctime, multiple consecutive syncs with k8s-apiserver are
	// batched and synced together after a short delay.
	DefaultCESSyncTime = 500 * time.Millisecond

	defaultMode = "default"
	slimMode    = "slim"
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
		workqueue.TypedRateLimitingQueueConfig[CESKey]{
			Name:            "cilium_endpoint_slice_fast",
			MetricsProvider: c.workqueueMetricsProvider,
		})
	c.standardQueue = workqueue.NewTypedRateLimitingQueueWithConfig(
		c.rateLimiter,
		workqueue.TypedRateLimitingQueueConfig[CESKey]{
			Name:            "cilium_endpoint_slice_standard",
			MetricsProvider: c.workqueueMetricsProvider,
		})
}

// isValidEndpoint reports whether a CiliumEndpoint has enough state to be
// placed into a CES. Endpoints missing Networking/Identity are being
// initialized by the agent and would produce invalid CoreCiliumEndpoint entries.
func isValidEndpoint(cep *cilium_api_v2.CiliumEndpoint) bool {
	return cep != nil &&
		cep.Status.Networking != nil &&
		cep.Status.Identity != nil &&
		cep.GetName() != "" &&
		cep.Namespace != ""
}

func (c *DefaultController) onEndpointUpdate(cep *cilium_api_v2.CiliumEndpoint) {
	if !isValidEndpoint(cep) {
		return
	}
	touchedCESs := c.manager.UpdateCEPMapping(k8s.ConvertCEPToCoreCEP(cep), cep.Namespace)
	c.enqueueCESReconciliation(touchedCESs)
}

func (c *DefaultController) onEndpointDelete(cep *cilium_api_v2.CiliumEndpoint) {
	touchedCES := c.manager.RemoveCEPMapping(k8s.ConvertCEPToCoreCEP(cep), cep.Namespace)
	c.enqueueCESReconciliation([]CESKey{touchedCES})
}

func (c *Controller) onSliceUpdate(ces *capi_v2a1.CiliumEndpointSlice) {
	c.enqueueCESReconciliation([]CESKey{NewCESKey(ces.Name, ces.Namespace)})
}

func (c *Controller) onSliceDelete(ces *capi_v2a1.CiliumEndpointSlice) {
	c.enqueueCESReconciliation([]CESKey{NewCESKey(ces.Name, ces.Namespace)})
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
func (c *DefaultController) Start(ctx cell.HookContext) error {
	// Processing CES/CEP events:
	// CES or CEP event is retrieved and checked whether it is from a priority namespace
	// Event is added to the fast queue if the namespace was priority and to the standard queue otherwise

	// Processing queues:
	// The controller checks if the fast queue and standard queue are empty
	// If yes, it waits on signal
	// if no, it checks if fast queue is empty
	// If no, it takes element from the fast queue. Otherwise it takes element from the standard queue.
	// CES from the queue is reconciled with the k8s api-server
	// if error appears while reconciling and maximum number of retries for this element has not been reached, it is added to the appropriate queue.
	// if the error has not appeared or the maximum number of retries has been reached, the element is forgotten.

	c.logger.InfoContext(ctx, "Bootstrap ces controller")
	defer utilruntime.HandleCrash()

	c.manager = newDefaultManager(c.maxCEPsInCES, c.logger)

	cepStore, _ := c.ciliumEndpoint.Store(ctx)
	cesStore, _ := c.ciliumEndpointSlice.Store(ctx)
	c.reconciler = newDefaultReconciler(c.clientset.CiliumV2alpha1(), c.manager, c.logger, cepStore, cesStore, c.metrics)
	c.doReconciler = c.reconciler

	c.initializeQueue()

	workerCtx, workerCancel := context.WithCancel(context.Background())
	// ensure the worker context is canceled if the Start context is canceled, to ensure it returns quickly.
	stop := context.AfterFunc(ctx, workerCancel)
	defer stop()

	// Subscribe before draining to avoid missing events between subscription
	// and drain (see syncCESsInLocalCache).
	ciliumEndpointEvents := c.ciliumEndpoint.Events(workerCtx)
	ciliumEndpointSliceEvents := c.ciliumEndpointSlice.Events(workerCtx)
	namespaceEvents := c.namespace.Events(workerCtx)

	if err := c.syncCESsInLocalCache(ciliumEndpointEvents, ciliumEndpointSliceEvents); err != nil {
		workerCancel()
		return err
	}

	c.Job.Add(
		job.OneShot("proc-ns-events", func(ctx context.Context, health cell.Health) error {
			return c.processNamespaceEvents(namespaceEvents)
		}),
	)
	// Start the work pools processing CEP events only after syncing CES in local cache.
	c.wp = workerpool.New(3)
	c.wp.Submit("cilium-endpoints-updater", func(ctx context.Context) error {
		return c.runCiliumEndpointsUpdater(ciliumEndpointEvents)
	})
	c.wp.Submit("cilium-endpoint-slices-updater", func(ctx context.Context) error {
		return c.runCiliumEndpointSliceUpdater(ciliumEndpointSliceEvents)
	})
	c.wp.Submit("cilium-nodes-updater", c.runCiliumNodesUpdater)

	c.logger.InfoContext(ctx, "Starting CES controller reconciler.")

	c.Job.Add(
		job.OneShot("proc-queues", func(_ context.Context, health cell.Health) error {
			c.worker(workerCtx)
			return nil
		}),
		// Add the shutdown job last so it stops first.
		job.OneShot("shutdown", func(ctx context.Context, health cell.Health) error {
			<-ctx.Done()
			workerCancel()
			c.wp.Close()
			c.fastQueue.ShutDown()
			c.standardQueue.ShutDown()
			return nil
		}),
	)

	return nil
}

// start the worker thread, reconciles the modified CESs with api-server
func (c *SlimController) Start(ctx cell.HookContext) error {
	// Processing CES/Pod events:
	// CES or Pod event is retrieved and checked whether it is from a priority namespace
	// Event is added to the fast queue if the namespace was priority and to the standard queue otherwise

	// Processing queues handled as with DefaultController.

	c.logger.InfoContext(ctx, "Bootstrap ces controller")
	defer utilruntime.HandleCrash()

	c.manager = newSlimManager(c.maxCEPsInCES, c.logger)

	cesStore, _ := c.ciliumEndpointSlice.Store(ctx)
	podStore, _ := c.pods.Store(ctx)
	ciStore, _ := c.ciliumIdentity.Store(ctx)
	cnodeStore, _ := c.ciliumNodes.Store(ctx)
	namespaceStore, _ := c.namespace.Store(ctx)
	c.reconciler = newSlimReconciler(c.clientset.CiliumV2alpha1(), c.manager, c.logger, cesStore, podStore, ciStore, cnodeStore, namespaceStore, c.metrics, c.ipsecEnabled, c.wgEnabled)
	c.doReconciler = c.reconciler

	c.initializeQueue()

	workerCtx, workerCancel := context.WithCancel(context.Background())
	// ensure the worker context is canceled if the Start context is canceled, to ensure it returns quickly.
	stop := context.AfterFunc(ctx, workerCancel)
	defer stop()

	// starts the events loop before syncCESsInLocalCache() to be sure we don't miss any event
	ciliumEndpointSliceEvents := c.ciliumEndpointSlice.Events(workerCtx)
	ciliumNodesEvents := c.ciliumNodes.Events(workerCtx)
	ciliumIdentityEvents := c.ciliumIdentity.Events(workerCtx)
	podsEvents := c.pods.Events(workerCtx)
	namespaceEvents := c.namespace.Events(workerCtx)

	if err := c.syncCESsInLocalCache(ciliumNodesEvents, ciliumIdentityEvents, ciliumEndpointSliceEvents, podsEvents); err != nil {
		workerCancel()
		return err
	}

	c.Job.Add(
		job.OneShot("proc-ns-events", func(ctx context.Context, health cell.Health) error {
			return c.processNamespaceEvents(namespaceEvents)
		}),
		job.OneShot("proc-pods-events", func(ctx context.Context, health cell.Health) error {
			return c.runCiliumPodsUpdater(podsEvents)
		}),
		job.OneShot("proc-ces-events", func(ctx context.Context, health cell.Health) error {
			return c.runCiliumEndpointSliceUpdater(ciliumEndpointSliceEvents)
		}),
		job.OneShot("proc-ciliumnodes-events", func(ctx context.Context, health cell.Health) error {
			return c.runCiliumNodesUpdater(ciliumNodesEvents)
		}),
		job.OneShot("proc-ciliumidentities-events", func(ctx context.Context, health cell.Health) error {
			return c.runCiliumIdentitiesUpdater(ciliumIdentityEvents)
		}),
		job.OneShot("proc-queues", func(_ context.Context, health cell.Health) error {
			c.worker(workerCtx)
			return nil
		}),
		// Add the shutdown job last so it stops first.
		job.OneShot("shutdown", func(ctx context.Context, health cell.Health) error {
			<-ctx.Done()
			c.fastQueue.ShutDown()
			c.standardQueue.ShutDown()
			workerCancel()
			return nil
		}),
	)

	c.logger.InfoContext(ctx, "Starting CES controller reconciler.")

	return nil
}

func (c *DefaultController) Stop(ctx cell.HookContext) error {
	return nil
}

func (c *SlimController) Stop(ctx cell.HookContext) error {
	return nil
}

func (c *DefaultController) runCiliumEndpointsUpdater(events <-chan resource.Event[*cilium_api_v2.CiliumEndpoint]) error {
	for event := range events {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert Endpoint event", logfields.CEPName, event.Key)
			c.onEndpointUpdate(event.Object)
		case resource.Delete:
			c.logger.Debug("Got Delete Endpoint event", logfields.CEPName, event.Key)
			c.onEndpointDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

func (c *SlimController) runCiliumPodsUpdater(events <-chan resource.Event[*slim_corev1.Pod]) error {
	for event := range events {
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

func (c *Controller) runCiliumEndpointSliceUpdater(events <-chan resource.Event[*capi_v2a1.CiliumEndpointSlice]) error {
	for event := range events {
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

func (c *DefaultController) runCiliumNodesUpdater(ctx context.Context) error {
	return runCiliumNodesUpdater(
		c.Controller,
		c.ciliumNodes.Events(ctx),
		nil,
	)
}

func (c *SlimController) runCiliumNodesUpdater(events <-chan resource.Event[*cilium_api_v2.CiliumNode]) error {
	return runCiliumNodesUpdater(
		c.Controller,
		events,
		func(event resource.Event[*cilium_api_v2.CiliumNode]) {
			switch event.Kind {
			case resource.Upsert:
				c.logger.Debug("Got Upsert CiliumNode event", logfields.NodeName, event.Key)
				c.onNodeUpdate(event.Object)
			case resource.Delete:
				c.logger.Debug("Got Delete CiliumNode event", logfields.NodeName, event.Key)
				c.onNodeDelete(event.Object)
			}
		},
	)
}

func runCiliumNodesUpdater(ctrlr *Controller,
	events <-chan resource.Event[*cilium_api_v2.CiliumNode],
	handleEvent func(event resource.Event[*cilium_api_v2.CiliumNode])) error {
	knownNodes := make(map[resource.Key]struct{})
	for event := range events {
		if handleEvent != nil {
			handleEvent(event)
		}
		switch event.Kind {
		case resource.Upsert:
			knownNodes[event.Key] = struct{}{}
		case resource.Delete:
			delete(knownNodes, event.Key)
		}
		event.Done(nil)
		if ctrlr.rateLimit.updateRateLimiterWithNodes(len(knownNodes)) {
			ctrlr.logger.Info("Updated CES controller workqueue configuration",
				logfields.WorkQueueQPSLimit, ctrlr.rateLimit.current.Limit,
				logfields.WorkQueueBurstLimit, ctrlr.rateLimit.current.Burst)
		}
	}
	return nil
}

func (c *SlimController) runCiliumIdentitiesUpdater(events <-chan resource.Event[*cilium_api_v2.CiliumIdentity]) error {
	for event := range events {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert CiliumIdentity event", logfields.CIDName, event.Key)
			c.onIdentityUpdate(event.Object)
		case resource.Delete:
			c.logger.Debug("Got Delete CiliumIdentity event", logfields.CIDName, event.Key)
			c.onIdentityDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

func (c *SlimController) onNodeUpdate(node *cilium_api_v2.CiliumNode) {
	touchedCESs := c.manager.UpdateNodeMapping(node, c.ipsecEnabled, c.wgEnabled)
	c.enqueueCESReconciliation(touchedCESs)
}

func (c *SlimController) onNodeDelete(node *cilium_api_v2.CiliumNode) {
	touchedCESs := c.manager.RemoveNodeMapping(node)
	c.enqueueCESReconciliation(touchedCESs)
}

func (c *SlimController) onIdentityUpdate(cid *cilium_api_v2.CiliumIdentity) {
	touchedCESs := c.manager.UpdateIdentityMapping(cid)
	c.enqueueCESReconciliation(touchedCESs)
}

func (c *SlimController) onIdentityDelete(cid *cilium_api_v2.CiliumIdentity) {
	touchedCESs := c.manager.RemoveIdentityMapping(cid)
	c.enqueueCESReconciliation(touchedCESs)
}

// On Pod Update, verify all the necessary fields are set.
// We recalculate the relevant fields when updating the CES instead of
// saving them here in case of any changes in value, to minimize the
// number of CES updates.
// Returns error if requires retry without pod update.
// resolvePodPlacement gathers the state needed to place a pod into a CES.
// Returns (node, cidKey, true) if the pod is placeable, or ("", nil, false)
// if it should be skipped (empty name/namespace, host-network, no IPs,
// unscheduled, or unresolvable labels). Errors are logged at debug level.
func (c *SlimController) resolvePodPlacement(pod *slim_corev1.Pod) (string, *key.GlobalIdentity, bool) {
	if pod.GetName() == "" || pod.GetNamespace() == "" {
		return "", nil, false
	}
	if pod.Spec.HostNetwork {
		// no CEP for host networking pods
		return "", nil, false
	}
	if _, err := GetPodEndpointNetworking(pod); err != nil {
		c.logger.Debug("could not get endpointnetworking for pod",
			logfields.K8sPodName, pod.Name,
			logfields.Error, err)
		// When pod is assigned IPs or scheduled, we will receive a new update.
		return "", nil, false
	}
	node, err := getNodeNameForPod(pod)
	if err != nil {
		c.logger.Debug("could not get node name for pod",
			logfields.K8sPodName, pod.Name,
			logfields.Error, err)
		// When pod is scheduled, we will receive a new update.
		return "", nil, false
	}
	cidKey, err := getPodCIDKey(pod, c.logger, c.reconciler.namespaceStore)
	if err != nil {
		c.logger.Debug("could not get labels for pod",
			logfields.K8sPodName, pod.Name,
			logfields.Error, err)
		return "", nil, false
	}
	return node, cidKey, true
}

func (c *SlimController) onPodUpdate(pod *slim_corev1.Pod) error {
	node, cidKey, ok := c.resolvePodPlacement(pod)
	if !ok {
		return nil
	}
	touchedCESs := c.manager.AddPodMapping(pod, node, cidKey)
	c.enqueueCESReconciliation(touchedCESs)
	return nil
}

func (c *SlimController) onPodDelete(pod *slim_corev1.Pod) {
	touchedCES := c.manager.RemovePodMapping(pod)
	c.enqueueCESReconciliation(touchedCES)
}

// syncCESsInLocalCache seeds the manager's CES↔CEP mapping from the CEP and
// CES event replays.
func (c *DefaultController) syncCESsInLocalCache(cepEvents <-chan resource.Event[*cilium_api_v2.CiliumEndpoint],
	cesEvents <-chan resource.Event[*capi_v2a1.CiliumEndpointSlice]) error {
	// Phase 1: snapshot live CEPs from the CEP replay.
	livecep := map[resource.Key]*cilium_api_v2.CiliumEndpoint{}
cepLoop:
	for event := range cepEvents {
		switch event.Kind {
		case resource.Upsert:
			if isValidEndpoint(event.Object) {
				livecep[event.Key] = event.Object
			}
		case resource.Delete:
			delete(livecep, event.Key)
		case resource.Sync:
			event.Done(nil)
			break cepLoop
		}
		event.Done(nil)
	}

	// Phase 2: seed the CES cache, skipping CEPs not in the phase-1 snapshot.
	var dirtyCESes []CESKey
cesLoop:
	for event := range cesEvents {
		switch event.Kind {
		case resource.Upsert:
			ces := event.Object
			cesName := c.manager.initializeMappingForCES(ces)
			stale := false
			for _, cep := range ces.Endpoints {
				cepKey := NewCEPName(cep.Name, ces.Namespace).key()
				if _, exists := livecep[cepKey]; exists {
					c.manager.initializeMappingCEPtoCES(&cep, ces.Namespace, cesName)
					delete(livecep, cepKey)
				} else {
					c.logger.Debug("Skipping stale CEP in CES during bootstrap",
						logfields.CESName, ces.Name,
						logfields.CEPName, cep.Name)
					stale = true
				}
			}
			if stale {
				dirtyCESes = append(dirtyCESes, NewCESKey(ces.Name, ces.Namespace))
			}
		case resource.Delete:
			// A CES we saw earlier in this replay has been deleted. Drop it
			// from the mapping and from dirtyCESes.
			cesName := CESName(event.Key.Name)
			for _, cep := range c.manager.mapping.getCEPsInCES(cesName) {
				c.manager.mapping.deleteCEP(cep)
			}
			c.manager.mapping.deleteCES(cesName)
			dirtyCESes = slices.DeleteFunc(dirtyCESes, func(k CESKey) bool {
				return k.Name == event.Key.Name && k.Namespace == event.Key.Namespace
			})
		case resource.Sync:
			event.Done(nil)
			break cesLoop
		}
		event.Done(nil)
	}

	// Phase 3: place orphan CEPs (no CES references them yet) into a CES.
	for _, cep := range livecep {
		c.onEndpointUpdate(cep)
	}

	c.enqueueCESReconciliation(dirtyCESes)
	c.logger.Debug("Successfully synced all CESs locally")
	return nil
}

// Sync all CESs from cesStore to manager cache.
// Note: CESs are synced locally before CES controller running and this is required.
func (c *SlimController) syncCESsInLocalCache(
	nodeEvents <-chan resource.Event[*cilium_api_v2.CiliumNode],
	identityEvents <-chan resource.Event[*cilium_api_v2.CiliumIdentity],
	cesEvents <-chan resource.Event[*capi_v2a1.CiliumEndpointSlice],
	podEvents <-chan resource.Event[*slim_corev1.Pod]) error {
	// Phase 1. Drain CiliumNode events up to Sync to build an IP → node-name map.
	nodeIPToName := make(map[string]string)
nodeLoop:
	for event := range nodeEvents {
		switch event.Kind {
		case resource.Upsert:
			node := event.Object
			for _, addr := range node.Spec.Addresses {
				nodeIPToName[addr.IP] = node.Name
			}
			c.manager.UpdateNodeMapping(node, c.ipsecEnabled, c.wgEnabled)
		case resource.Delete:
			node := event.Object
			for _, addr := range node.Spec.Addresses {
				delete(nodeIPToName, addr.IP)
			}
			c.manager.RemoveNodeMapping(node)
		case resource.Sync:
			event.Done(nil)
			break nodeLoop
		}
		event.Done(nil)
	}

	// Phase 2. Drain CiliumIdentity events up to Sync to build the CID → labels map.
	cidToLabels := make(map[CID]Labels)
identityLoop:
	for event := range identityEvents {
		switch event.Kind {
		case resource.Upsert:
			cid := event.Object
			cidName, gidLabels := cidToGidLabels(cid)
			cidToLabels[cidName] = gidLabels
			c.manager.UpdateIdentityMapping(cid)
		case resource.Delete:
			cid := event.Object
			cidName, _ := cidToGidLabels(cid)
			delete(cidToLabels, cidName)
			c.manager.RemoveIdentityMapping(cid)
		case resource.Sync:
			event.Done(nil)
			break identityLoop
		}
		event.Done(nil)
	}

	// Phase 3. Drain Pod events up to Sync into livepods. We only build the
	// map here — placement into CESes must wait until after the CES-drain
	// has populated the CES cache; otherwise AddPodMapping would find no
	// existing CES and create a phantom one.
	livepods := make(map[CEPName]*slim_corev1.Pod)
podLoop:
	for event := range podEvents {
		switch event.Kind {
		case resource.Upsert:
			pod := event.Object
			if _, _, ok := c.resolvePodPlacement(pod); ok {
				livepods[GetCEPNameFromPod(pod)] = pod
			}
		case resource.Delete:
			pod := event.Object
			delete(livepods, GetCEPNameFromPod(pod))
		case resource.Sync:
			event.Done(nil)
			break podLoop
		}
		event.Done(nil)
	}

	var dirtyCESes []CESKey

	// Phase 4. Drain CiliumEndpointSlice events up to Sync, applying each
	// seen CES to the manager cache. Uses livepods for the stale-CEP check.
cesLoop:
	for event := range cesEvents {
		switch event.Kind {
		case resource.Upsert:
			ces := event.Object
			c.manager.initializeMappingForCES(ces)
			stale := false
			for _, cep := range ces.Endpoints {
				cepName := NewCEPName(cep.Name, ces.Namespace)
				// If the Pod is not found (e.g., deleted during operator
				// restart), skip restoring the CEP so it doesn't inflate
				// the CES capacity count in the local cache.
				if _, ok := livepods[cepName]; !ok {
					c.logger.Debug("Pod not found for CEP during bootstrap; skipping",
						logfields.CEPName, cep.Name)
					stale = true
					continue
				}

				identityid := strconv.FormatInt(cep.IdentityID, 10)
				labels, ok := cidToLabels[CID(identityid)]
				// If the CID is not found (e.g., deleted during operator restart), we skip restoring the state of this CEP on startup.
				// We will get the CEP & CID add events through the resource stores and update the latest state in the local cache.
				if !ok {
					c.logger.Debug("CID not found in Store for CEP",
						logfields.CIDName, identityid,
						logfields.CEPName, cep.Name)
					stale = true
					continue
				}

				nodeName, ok := nodeIPToName[cep.Networking.NodeIP]
				// If the CiliumNode is not found (e.g., deleted during operator restart), we skip restoring the state of this CEP on startup.
				// We will get the CEP & CiliumNode add events through the resource stores and update the latest state in the local cache.
				if !ok {
					c.logger.Debug("CiliumNode not found for CEP node IP",
						logfields.IPAddr, cep.Networking.NodeIP,
						logfields.CEPName, cep.Name)
					stale = true
					continue
				}

				c.manager.initializeMappingPodToNode(NewCEPName(cep.Name, ces.Namespace), NodeName(nodeName), CESName(ces.Name), CID(identityid), Labels(labels), EncryptionKey(cep.Encryption.Key))
				// The pod is now accounted for in the CES cache; drop it
				// from livepods so phase 5 doesn't try to place it again.
				delete(livepods, cepName)
			}

			if stale {
				dirtyCESes = append(dirtyCESes, NewCESKey(ces.Name, ces.Namespace))
			}
		case resource.Delete:
			// A CES we may have seeded above has been deleted during bootstrap;
			// drop it from the mapping and from dirtyCESes so we don't
			// enqueue an already-deleted CES.
			cesName := CESName(event.Object.Name)
			for _, cep := range c.manager.mapping.getCEPsInCES(cesName) {
				c.manager.mapping.deleteCEP(cep)
			}
			c.manager.mapping.deleteCES(cesName)
			dirtyCESes = slices.DeleteFunc(dirtyCESes, func(k CESKey) bool {
				return k.Name == event.Object.Name && k.Namespace == event.Object.Namespace
			})
		case resource.Sync:
			event.Done(nil)
			break cesLoop
		}
		event.Done(nil)
	}

	c.enqueueCESReconciliation(dirtyCESes)

	// Phase 5: place any remaining pods (those not already accounted for by
	// an existing CES).
	for _, pod := range livepods {
		c.onPodUpdate(pod)
	}

	c.logger.Debug("Successfully synced all CESs locally")
	return nil
}

// worker runs a worker thread that just dequeues items, processes them, and
// marks them done.
func (c *Controller) worker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *Controller) rateLimitProcessing(ctx context.Context) {
	delay := c.rateLimit.getDelay()
	select {
	case <-ctx.Done():
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

func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	c.rateLimitProcessing(ctx)
	queue := c.getQueue()
	key, quit := queue.Get()
	if quit {
		return false
	}
	defer queue.Done(key)

	c.logger.Debug("Processing CES", logfields.CESName, key.string())

	queueDelay := c.getAndResetCESProcessingDelay(key)
	err := c.doReconciler.reconcileCES(ctx, CESName(key.Name))
	if queue == c.fastQueue {
		c.metrics.CiliumEndpointSliceQueueDelay.WithLabelValues(LabelQueueFast).Observe(queueDelay)
	} else {
		c.metrics.CiliumEndpointSliceQueueDelay.WithLabelValues(LabelQueueStandard).Observe(queueDelay)
	}

	isRetried := c.handleErr(queue, err, key)
	if err != nil {
		if isRetried {
			c.metrics.CiliumEndpointSliceSyncTotal.WithLabelValues(LabelValueOutcomeFail, LabelFailureTypeTransient).Inc()
		} else {
			c.metrics.CiliumEndpointSliceSyncTotal.WithLabelValues(LabelValueOutcomeFail, LabelFailureTypeFatal).Inc()
		}
	} else {
		c.metrics.CiliumEndpointSliceSyncTotal.WithLabelValues(LabelValueOutcomeSuccess, "").Inc()
	}

	return true
}

func (c *Controller) handleErr(queue workqueue.TypedRateLimitingInterface[CESKey], err error, key CESKey) (retry bool) {
	if err == nil {
		queue.Forget(key)
		return false
	}

	if queue.NumRequeues(key) < maxRetries {
		if !k8serrors.IsConflict(err) && !k8serrors.IsAlreadyExists(err) && !k8serrors.IsNotFound(err) && !(k8serrors.IsForbidden(err) && k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause)) {
			c.logger.Warn("Error processing CES, retrying",
				logfields.CESName, key.string(),
				logfields.Error, err,
				logfields.Attempt, queue.NumRequeues(key)+1)
		}
		time.AfterFunc(c.rateLimiter.When(key), func() {
			c.cond.L.Lock()
			defer c.cond.L.Unlock()
			queue.Add(key)
			c.cond.Signal()
		})
		return true
	}

	// Drop the CES from queue, we maxed out retries.
	c.logger.Error("Dropping the CES from queue, exceeded maxRetries",
		logfields.CESName, key.string(),
		logfields.Error, err)
	queue.Forget(key)
	return false
}
