// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"fmt"
	"time"

	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	ciliumV2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
)

// params contains all the dependencies for the identity-gc.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle hive.Lifecycle

	Clientset k8sClient.Clientset
	Identity  resource.Resource[*v2.CiliumIdentity]

	Cfg       Config
	SharedCfg SharedConfig
}

// GC represents the Cilium identities periodic GC.
type GC struct {
	logger logrus.FieldLogger

	clientset ciliumV2.CiliumIdentityInterface
	identity  resource.Resource[*v2.CiliumIdentity]

	allocationMode string

	gcInterval       time.Duration
	heartbeatTimeout time.Duration
	gcRateInterval   time.Duration
	gcRateLimit      int64

	wp             *workerpool.WorkerPool
	heartbeatStore *heartbeatStore
	mgr            *controller.Manager

	// rateLimiter is meant to rate limit the number of
	// identities being GCed by the operator. See the documentation of
	// rate.Limiter to understand its difference than 'x/time/rate.Limiter'.
	//
	// With our rate.Limiter implementation Cilium will be able to handle bursts
	// of identities being garbage collected with the help of the functionality
	// provided by the 'policy-trigger-interval' in the cilium-agent. With the
	// policy-trigger even if we receive N identity changes over the interval
	// set, Cilium will only need to process all of them at once instead of
	// processing each one individually.
	rateLimiter *rate.Limiter

	allocationCfg identityAllocationConfig
	allocator     *allocator.Allocator

	enableMetrics bool
	// counters for GC failed/successful runs
	failedRuns     int
	successfulRuns int
}

func registerGC(p params) {
	if !p.Clientset.IsEnabled() {
		return
	}

	gc := &GC{
		logger:           p.Logger,
		clientset:        p.Clientset.CiliumV2().CiliumIdentities(),
		identity:         p.Identity,
		allocationMode:   p.SharedCfg.IdentityAllocationMode,
		gcInterval:       p.Cfg.Interval,
		heartbeatTimeout: p.Cfg.HeartbeatTimeout,
		gcRateInterval:   p.Cfg.RateInterval,
		gcRateLimit:      p.Cfg.RateLimit,
		heartbeatStore: newHeartbeatStore(
			p.Cfg.HeartbeatTimeout,
		),
		rateLimiter: rate.NewLimiter(
			p.Cfg.RateInterval,
			p.Cfg.RateLimit,
		),
		allocationCfg: identityAllocationConfig{
			clusterName:  p.SharedCfg.ClusterName,
			k8sNamespace: p.SharedCfg.K8sNamespace,
			clusterID:    p.SharedCfg.ClusterID,
		},
	}
	p.Lifecycle.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			gc.wp = workerpool.New(1)

			switch gc.allocationMode {
			case option.IdentityAllocationModeCRD:
				return gc.startCRDModeGC(ctx)
			case option.IdentityAllocationModeKVstore:
				return gc.startKVStoreModeGC(ctx)
			default:
				return fmt.Errorf("unknown Cilium identity allocation mode: %q", gc.allocationMode)
			}
		},
		OnStop: func(ctx hive.HookContext) error {
			if gc.allocationMode == option.IdentityAllocationModeCRD {
				// CRD mode GC runs in an additional goroutine
				gc.mgr.RemoveAllAndWait()
			}
			gc.rateLimiter.Stop()
			gc.wp.Close()

			return nil
		},
	})
}

// identityAllocationConfig is a helper struct that satisfies the Configuration interface.
type identityAllocationConfig struct {
	clusterName  string
	k8sNamespace string
	clusterID    uint32
}

func (cfg identityAllocationConfig) LocalClusterName() string {
	return cfg.clusterName
}

func (cfg identityAllocationConfig) CiliumNamespaceName() string {
	return cfg.k8sNamespace
}

func (cfg identityAllocationConfig) LocalClusterID() uint32 {
	return cfg.clusterID
}
