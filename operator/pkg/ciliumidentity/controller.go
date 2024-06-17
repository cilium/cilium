// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"log/slog"
	"time"

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
	}

	p.Lifecycle.Append(cidController)
}

func (c *Controller) Start(hookContext cell.HookContext) error {
	//TODO implement me
	panic("implement me")
}

func (c *Controller) Stop(hookContext cell.HookContext) error {
	//TODO implement me
	panic("implement me")
}
