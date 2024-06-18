// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/cilium/hive/cell"
	"github.com/cilium/workerpool"
	"k8s.io/client-go/util/workqueue"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
)

const (
	// defaultSyncBackOff is the default backoff period for cesSync calls.
	defaultSyncBackOff = 1 * time.Second
	// maxSyncBackOff is the max backoff period for cesSync calls.
	maxSyncBackOff = 100 * time.Second
	// maxRetries is the number of times a work queue sync will be retried before
	// it is dropped out of the queue.
	maxProcessRetries = 15
	workerPoolSize    = 6
)

var (
	// cidDeleteDelay is the delay to enqueue another CID event to be reconciled
	// after CID is marked for deletion. This is required for simultaneous CID
	// management by both cilium-operator and cilium-agent. Without the delay,
	// operator might immediately clean up CIDs created by agent, before agent can
	// finish CEP creation.
	cidDeleteDelay = 30 * time.Second
)

type queueOperations interface {
	enqueueCIDReconciliation(cidKey resource.Key, delay time.Duration)
	enqueuePodReconciliation(podKey resource.Key, delay time.Duration)
}

type params struct {
	cell.In

	Logger              *slog.Logger
	Lifecycle           cell.Lifecycle
	Clientset           k8sClient.Clientset
	SharedCfg           SharedConfig
	Metrics             *Metrics
	Namespace           resource.Resource[*slim_corev1.Namespace]
	Pod                 resource.Resource[*slim_corev1.Pod]
	CiliumIdentity      resource.Resource[*cilium_api_v2.CiliumIdentity]
	CiliumEndpoint      resource.Resource[*cilium_api_v2.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]
}

type Controller struct {
	logger              *slog.Logger
	context             context.Context
	contextCancel       context.CancelFunc
	metrics             *Metrics
	clientset           k8sClient.Clientset
	reconciler          *reconciler
	namespace           resource.Resource[*slim_corev1.Namespace]
	pod                 resource.Resource[*slim_corev1.Pod]
	ciliumIdentity      resource.Resource[*cilium_api_v2.CiliumIdentity]
	ciliumEndpoint      resource.Resource[*cilium_api_v2.CiliumEndpoint]
	ciliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]

	// Work queues are used to sync resources with the api-server.
	// Work queues will rate-limit requests going to api-server. Ensures a single
	// resource key will not be processed multiple times concurrently, and if
	// a resource key is added multiple times before it can be processed, this
	// will only be processed once.
	cidQueue      workqueue.RateLimitingInterface
	podQueue      workqueue.RateLimitingInterface
	cidEnqueuedAt *EnqueueTimeTracker
	podEnqueuedAt *EnqueueTimeTracker

	wp         *workerpool.WorkerPool
	cesEnabled bool

	// oldNSSecurityLabels is a map between namespace, and it's security labels.
	// It's used to track previous state of labels, to detect when labels changed.
	oldNSSecurityLabels map[string]labels.Labels
}

func registerController(p params) {
	if !p.Clientset.IsEnabled() || !p.SharedCfg.EnableOperatorManageCIDs {
		return
	}

	cidController := &Controller{
		logger:              p.Logger,
		clientset:           p.Clientset,
		namespace:           p.Namespace,
		pod:                 p.Pod,
		ciliumIdentity:      p.CiliumIdentity,
		ciliumEndpoint:      p.CiliumEndpoint,
		ciliumEndpointSlice: p.CiliumEndpointSlice,
		cidEnqueuedAt:       &EnqueueTimeTracker{enqueuedAt: make(map[string]time.Time)},
		podEnqueuedAt:       &EnqueueTimeTracker{enqueuedAt: make(map[string]time.Time)},
		oldNSSecurityLabels: make(map[string]labels.Labels),
		cesEnabled:          p.SharedCfg.EnableCiliumEndpointSlice,
		metrics:             p.Metrics,
	}

	// TODO Read identity relevant labels from ConfigMap to update the labelsfilter

	cidController.initializeQueues()

	p.Lifecycle.Append(cidController)
}

func (c *Controller) Start(_ cell.HookContext) error {
	c.logger.Info("Starting CID controller Operator")
	defer utilruntime.HandleCrash()

	c.context, c.contextCancel = context.WithCancel(context.Background())
	c.reconciler = newReconciler(
		c.context,
		c.logger,
		c.clientset,
		c.namespace,
		c.pod,
		c.ciliumIdentity,
		c.ciliumEndpoint,
		c.ciliumEndpointSlice,
		c.cesEnabled,
		c,
	)

	c.logger.Info("Starting CID controller reconciler")

	// The desired state needs to be calculated before the events are processed.
	if err := c.reconciler.calcDesiredStateOnStartup(); err != nil {
		return fmt.Errorf("cid controller failed to calculate the desired state: %w", err)
	}

	// The Cilium Identity (CID) controller running in cilium-operator is
	// responsible only for managing CID API objects.
	//
	// Pod events are added to Pod work queue.
	// Namespace events are processed immediately and added to Pod work queue.
	// CID events are added to CID work queue.
	// Processing Pod work queue items are adding items to CID work queue.
	// Processed CID work queue items result in mutations to CID API objects.
	//
	// Diagram:
	//-------------------------Pod event---------CID event
	//---------------------------||-----------------||
	//----------------------------V------------------V
	// Namespace event -> Pod work queue -> CID work queue -> Mutate CID API objects
	c.wp = workerpool.New(workerPoolSize)
	err := c.startEventProcessing()
	if err != nil {
		return err
	}
	err = c.startWorkQueues()
	if err != nil {
		return err
	}

	return nil
}

func (c *Controller) Stop(_ cell.HookContext) error {
	c.cidQueue.ShutDown()
	c.podQueue.ShutDown()

	c.contextCancel()
	return c.wp.Close()
}

func (c *Controller) initializeQueues() {
	c.initCIDQueue()
	c.initPodQueue()
}

func (c *Controller) startEventProcessing() error {
	if err := c.wp.Submit("proc-cid-events", c.processCiliumIdentityEvents); err != nil {
		return fmt.Errorf("failed to init worker pool for CiliumIdentityEvents")
	}
	if err := c.wp.Submit("proc-pod-events", c.processPodEvents); err != nil {
		return fmt.Errorf("failed to init worker pool for PodEvents")
	}
	if err := c.wp.Submit("proc-ces-events", c.processCiliumEndpointSliceEvents); err != nil {
		return fmt.Errorf("failed to init worker pool for CiliumEndpointSliceEvents")
	}
	if err := c.wp.Submit("proc-ns-events", c.processNamespaceEvents); err != nil {
		return err
	}
	return nil
}

func (c *Controller) startWorkQueues() error {
	if err := c.wp.Submit("op-managing-cid-wq", c.runCIDWorker); err != nil {
		return fmt.Errorf("failed to init worker pool for CID Worker")
	}
	if err := c.wp.Submit("op-managing-pod-wq", c.runPodWorker); err != nil {
		return fmt.Errorf("failed to init worker pool for Pod Worker")
	}
	return nil
}
