// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/workqueue"
)

const (
	// defaultSyncBackOff is the default backoff period for cesSync calls.
	defaultSyncBackOff = 1 * time.Second
	// maxSyncBackOff is the max backoff period for cesSync calls.
	maxSyncBackOff = 100 * time.Second
	// maxRetries is the number of times a workqueue sync will be retried before
	// it is dropped out of the queue.
	maxProcessRetries = 15
)

var (
	// cidDeleteDelay is the delay to enqueue another CID event to be reconciled
	// after CID is marked for deletion. This is required for simultaneous CID
	// management by both cilium-operator and cilium-agent. Without the delay,
	// operator might immediately clean up CIDs created by agent, before agent can
	// finish CEP creation.
	cidDeleteDelay = 30 * time.Second
)

// params contains all the dependencies for the Cilium Identity controller.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle

	Namespace           resource.Resource[*slim_corev1.Namespace]
	Pod                 resource.Resource[*slim_corev1.Pod]
	CiliumIdentity      resource.Resource[*cilium_api_v2.CiliumIdentity]
	CiliumEndpoint      resource.Resource[*cilium_api_v2.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]
	Clientset           k8sClient.Clientset

	Cfg       Config
	SharedCfg SharedConfig
	Metrics   *Metrics
}

type Controller struct {
	logger        logrus.FieldLogger
	context       context.Context
	contextCancel context.CancelFunc
	metrics       *Metrics

	clientset  k8sClient.Clientset
	reconciler *reconciler

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
	cidQueue workqueue.RateLimitingInterface
	podQueue workqueue.RateLimitingInterface

	cidEnqueuedAt *EnqueueTimeTracker
	podEnqueuedAt *EnqueueTimeTracker

	// oldNSSecurityLabels is a map between namespace and it's security labels.
	// It's used to track preivous state of labels, to detect when labels changed.
	oldNSSecurityLabels map[string]labels.Labels

	wp *workerpool.WorkerPool

	cesEnabled            bool
	googleMultiNICEnabled bool
}

type queueOperations interface {
	enqueueCIDReconciliation(cidKey resource.Key, delay time.Duration)
	enqueuePodReconciliation(podKey resource.Key, delay time.Duration)
}

type queueItem struct {
	key         resource.Key
	enqueueTime time.Time
}

// registerController creates and initializes the CID controller
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

	cidController.getIDRelevantLabelsFilter()
	cidController.initializeQueues()

	p.Lifecycle.Append(cidController)
}

func (c *Controller) Start(ctx cell.HookContext) error {
	c.logger.Info("Starting Cilium Identity controller")
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

	c.logger.Info("Starting CID controller reconciler.")

	// The desired state needs to be calculated before the events are processed.
	if err := c.reconciler.calcDesiredStateOnStartup(); err != nil {
		return fmt.Errorf("CID controller failed to calculate the desired state: %v", err)
	}

	// The Cilium Identity (CID) controller running in cilium-operator is
	// responsible only for managing CID API objects.
	//
	// Pod events are added to Pod workqueue.
	// Namespace events are processed immediately and added also to Pod workqueue.
	// CID events are added to CID workqueue.
	// Processing Pod workqueue items are adding items to CID workqueue.
	// Processed CID workqueue items result in mutations to CID API objects.
	//
	// Diagram:
	//-----------------------Pod event--------CID event
	//-------------------------||---------------||
	//--------------------------V----------------V
	// Namespace event -> Pod workqueue -> CID workqueue -> Mutate CID API objects
	c.wp = workerpool.New(6)
	c.startEventProcessing()
	c.startWorkQueues()

	return nil
}

func (c *Controller) Stop(ctx cell.HookContext) error {
	c.cidQueue.ShutDown()
	c.podQueue.ShutDown()

	c.contextCancel()
	return c.wp.Close()
}

func (c *Controller) initializeQueues() {
	c.initCIDQueue()
	c.initPodQueue()
}

func (c *Controller) startEventProcessing() {
	c.wp.Submit("process-cilium-identity-events", c.processCiliumIdentityEvents)
	c.wp.Submit("process-pod-events", c.processPodEvents)
	c.wp.Submit("process-namespace-events", c.processNamespaceEvents)
	c.wp.Submit("process-cilium-endpoint-slice-events", c.processCiliumEndpointSliceEvents)
}

func (c *Controller) startWorkQueues() {
	c.wp.Submit("cilium-identity-workqueue-worker", c.runCIDWorker)
	c.wp.Submit("pod-workqueue-worker", c.runPodWorker)
}
