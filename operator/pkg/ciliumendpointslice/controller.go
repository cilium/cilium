// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/workerpool"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	wgAgent "github.com/cilium/cilium/pkg/wireguard/agent"
)

// params contains all the dependencies for the CiliumEndpointSlice controller.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle

	NewClient           k8sClient.ClientBuilderFunc
	CiliumEndpoint      resource.Resource[*v2.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]
	CiliumNodes         resource.Resource[*v2.CiliumNode]
	Namespace           resource.Resource[*slim_corev1.Namespace]
	Pods                resource.Resource[*slim_corev1.Pod]
	CiliumIdentity      resource.Resource[*v2.CiliumIdentity]

	Cfg          Config
	SharedCfg    SharedConfig
	IPSecCfg     ipsec.EnableConfig
	WireguardCfg wgAgent.EnableConfig

	Metrics                  *Metrics
	WorkqueueMetricsProvider workqueue.MetricsProvider

	Job job.Group
}

type Controller struct {
	logger        *slog.Logger
	context       context.Context
	contextCancel context.CancelFunc

	// Cilium kubernetes clients to access V2 and V2alpha1 resources
	clientset           k8sClient.Clientset
	ciliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]
	ciliumNodes         resource.Resource[*v2.CiliumNode]
	namespace           resource.Resource[*slim_corev1.Namespace]

	maxCEPsInCES int

	// workqueue is used to sync CESs with the api-server. this will rate-limit the
	// CES requests going to api-server, ensures a single CES will not be proccessed
	// multiple times concurrently, and if CES is added multiple times before it
	// can be processed, this will only be processed only once.
	// Updates from CEP and CES in namespaces annotated as priority are added to the
	// fast queue and processed first to ensure faster enforcement of the
	// Network Policy in critical areas.
	fastQueue     workqueue.TypedRateLimitingInterface[CESKey]
	standardQueue workqueue.TypedRateLimitingInterface[CESKey]

	rateLimit   rateLimitConfig
	rateLimiter workqueue.TypedRateLimiter[CESKey]

	enqueuedAt     map[CESKey]time.Time
	enqueuedAtLock lock.Mutex

	metrics                  *Metrics
	workqueueMetricsProvider workqueue.MetricsProvider

	syncDelay time.Duration

	priorityNamespaces     map[string]struct{}
	priorityNamespacesLock lock.RWMutex

	doReconciler doReconciler

	// If the queues are empty, they wait until the condition (adding something to the queues) is met.
	cond sync.Cond

	Job job.Group
}

// DefaultController is the CES controller running in default mode, creating CES
// from CEPs.
type DefaultController struct {
	*Controller

	// Manager is used to create and maintain a local datastore. Manager watches for
	// cilium endpoint changes and enqueues/dequeues the cilium endpoint changes in CES.
	// It maintains the desired state of the CESs in dataStore
	manager *defaultManager

	// reconciler is an util used to reconcile CiliumEndpointSlice changes.
	reconciler *defaultReconciler

	ciliumEndpoint resource.Resource[*v2.CiliumEndpoint]

	wp *workerpool.WorkerPool
}

// SlimController is the CES controller running in slim mode, creating CES
// from Pods.
type SlimController struct {
	*Controller

	// Manager is used to create and maintain a local datastore. Manager watches for
	// pod changes and enqueues/dequeues the pod changes in CES.
	// It maintains the desired state of the CESs in dataStore
	manager *slimManager

	// reconciler is an util used to reconcile CiliumEndpointSlice changes.
	reconciler *slimReconciler

	ipsecEnabled bool
	wgEnabled    bool

	ciliumIdentity resource.Resource[*v2.CiliumIdentity]
	pods           resource.Resource[*slim_corev1.Pod]
}

// registerController creates and initializes the CES controller
func registerController(p params) error {
	clientset, err := p.NewClient("ciliumendpointslice-controller")
	if err != nil {
		return err
	}
	if !clientset.IsEnabled() || !p.SharedCfg.EnableCiliumEndpointSlice {
		return nil
	}

	rateLimitConfig, err := getRateLimitConfig(p)
	if err != nil {
		return err
	}

	if p.Cfg.CESControllerMode != defaultMode && p.Cfg.CESControllerMode != slimMode {
		return fmt.Errorf("Invalid CES controller mode: %s", p.Cfg.CESControllerMode)
	}

	cesController := &Controller{
		logger:                   p.Logger,
		clientset:                clientset,
		ciliumEndpointSlice:      p.CiliumEndpointSlice,
		ciliumNodes:              p.CiliumNodes,
		namespace:                p.Namespace,
		maxCEPsInCES:             p.Cfg.CESMaxCEPsInCES,
		rateLimit:                rateLimitConfig,
		enqueuedAt:               make(map[CESKey]time.Time),
		metrics:                  p.Metrics,
		workqueueMetricsProvider: p.WorkqueueMetricsProvider,
		syncDelay:                DefaultCESSyncTime,
		priorityNamespaces:       make(map[string]struct{}),
		cond:                     *sync.NewCond(&lock.Mutex{}),
		Job:                      p.Job,
	}

	if p.Cfg.CESControllerMode == defaultMode {
		p.Logger.Info("CES Controller running in default mode")
		defaultController := &DefaultController{
			Controller:     cesController,
			ciliumEndpoint: p.CiliumEndpoint,
		}
		p.Lifecycle.Append(defaultController)
	} else {
		p.Logger.Info("CES Controller running in slim mode")
		slimController := &SlimController{
			Controller:     cesController,
			ciliumIdentity: p.CiliumIdentity,
			pods:           p.Pods,
			ipsecEnabled:   p.IPSecCfg.Enabled(),
			wgEnabled:      p.WireguardCfg.Enabled(),
		}
		p.Lifecycle.Append(slimController)
	}

	return nil
}
