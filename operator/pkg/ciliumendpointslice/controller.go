// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"sync"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
)

// params contains all the dependencies for the CiliumEndpointSlice controller.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle

	NewClient           k8sClient.ClientBuilderFunc
	CiliumEndpoint      resource.Resource[*v2.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]
	CiliumNodes         resource.Resource[*v2.CiliumNode]
	Namespace           resource.Resource[*slim_corev1.Namespace]

	Cfg       Config
	SharedCfg SharedConfig

	Metrics *Metrics

	Job job.Group
}

type Controller struct {
	logger        logrus.FieldLogger
	context       context.Context
	contextCancel context.CancelFunc

	// Cilium kubernetes clients to access V2 and V2alpha1 resources
	clientset           k8sClient.Clientset
	ciliumEndpoint      resource.Resource[*v2.CiliumEndpoint]
	ciliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]
	ciliumNodes         resource.Resource[*v2.CiliumNode]
	namespace           resource.Resource[*slim_corev1.Namespace]
	// reconciler is an util used to reconcile CiliumEndpointSlice changes.
	reconciler *reconciler

	// Manager is used to create and maintain a local datastore. Manager watches for
	// cilium endpoint changes and enqueues/dequeues the cilium endpoint changes in CES.
	// It maintains the desired state of the CESs in dataStore
	manager      operations
	slicingMode  string
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

	wp *workerpool.WorkerPool

	metrics *Metrics

	syncDelay time.Duration

	priorityNamespaces     map[string]struct{}
	priorityNamespacesLock lock.RWMutex

	// If the queues are empty, they wait until the condition (adding something to the queues) is met.
	cond sync.Cond

	Job job.Group
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

	checkDeprecatedOpts(p.Cfg, p.Logger)

	cesController := &Controller{
		logger:              p.Logger,
		clientset:           clientset,
		ciliumEndpoint:      p.CiliumEndpoint,
		ciliumEndpointSlice: p.CiliumEndpointSlice,
		ciliumNodes:         p.CiliumNodes,
		namespace:           p.Namespace,
		slicingMode:         p.Cfg.CESSlicingMode,
		maxCEPsInCES:        p.Cfg.CESMaxCEPsInCES,
		rateLimit:           rateLimitConfig,
		enqueuedAt:          make(map[CESKey]time.Time),
		metrics:             p.Metrics,
		syncDelay:           DefaultCESSyncTime,
		priorityNamespaces:  make(map[string]struct{}),
		cond:                *sync.NewCond(&lock.Mutex{}),
		Job:                 p.Job,
	}
	p.Lifecycle.Append(cesController)
	return nil
}

// checkDeprecatedOpts will log an error if the user has supplied any of the
// no-op, deprecated rate limit options.
// TODO: Remove this function when the deprecated options are removed.
func checkDeprecatedOpts(cfg Config, logger logrus.FieldLogger) {
	switch {
	case cfg.CESWriteQPSLimit > 0:
	case cfg.CESWriteQPSBurst > 0:
	case cfg.CESEnableDynamicRateLimit:
	case len(cfg.CESDynamicRateLimitNodes) > 0:
	case len(cfg.CESDynamicRateLimitQPSLimit) > 0:
	case len(cfg.CESDynamicRateLimitQPSBurst) > 0:
	default:
		return
	}
	logger.Errorf("You are using deprecated rate limit option(s) that have no effect. To configure custom rate limits please use --%s", CESRateLimits)
}
