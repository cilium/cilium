// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"time"

	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
)

// params contains all the dependencies for the CiliumEndpointSlice controller.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle hive.Lifecycle

	Clientset           k8sClient.Clientset
	CiliumEndpoint      resource.Resource[*v2.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]

	Cfg       Config
	SharedCfg SharedConfig

	Metrics *Metrics
}

type Controller struct {
	logger        logrus.FieldLogger
	context       context.Context
	contextCancel context.CancelFunc

	// Cilium kubernetes clients to access V2 and V2alpha1 resources
	clientset           k8sClient.Clientset
	ciliumEndpoint      resource.Resource[*v2.CiliumEndpoint]
	ciliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]

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
	queue            workqueue.RateLimitingInterface
	queueRateLimiter *rate.Limiter
	writeQPSLimit    float64
	writeQPSBurst    int

	enqueuedAt     map[CESName]time.Time
	enqueuedAtLock lock.Mutex

	wp *workerpool.WorkerPool

	metrics *Metrics
}

// registerController creates and initializes the CES controller
func registerController(p params) {
	if !p.Clientset.IsEnabled() || !p.SharedCfg.EnableCiliumEndpointSlice {
		return
	}

	cesController := &Controller{
		logger:              p.Logger,
		clientset:           p.Clientset,
		ciliumEndpoint:      p.CiliumEndpoint,
		ciliumEndpointSlice: p.CiliumEndpointSlice,
		slicingMode:         p.Cfg.CESSlicingMode,
		maxCEPsInCES:        p.Cfg.CESMaxCEPsInCES,
		writeQPSLimit:       p.Cfg.CESWriteQPSLimit,
		writeQPSBurst:       p.Cfg.CESWriteQPSBurst,
		enqueuedAt:          make(map[CESName]time.Time),
		metrics:             p.Metrics,
	}

	p.Lifecycle.Append(cesController)
}
