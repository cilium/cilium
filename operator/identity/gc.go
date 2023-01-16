// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

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

// Start implements hive.HookInterface
func (igc *GC) Start(ctx hive.HookContext) error {
	switch igc.allocationMode {
	case option.IdentityAllocationModeCRD:
		return igc.startCRDModeGC(ctx)
	case option.IdentityAllocationModeKVstore:
		return igc.startKVStoreModeGC(ctx)
	default:
		return fmt.Errorf("unknown Cilium identity allocation mode: %q", igc.allocationMode)
	}
}

// Stop implements hive.HookInterface
func (igc *GC) Stop(ctx hive.HookContext) error {
	switch igc.allocationMode {
	case option.IdentityAllocationModeCRD:
		// CRD mode GC runs in an additional goroutine
		igc.mgr.RemoveAllAndWait()
	}

	igc.rateLimiter.Stop()
	igc.wp.Close()

	return nil
}

// gcParams contains all the dependencies for the identity-gc.
// They will be provided through dependency injection.
type gcParams struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle hive.Lifecycle

	Clientset k8sClient.Clientset
	Identity  resource.Resource[*v2.CiliumIdentity]

	Cfg       GCConfig
	SharedCfg GCSharedConfig
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
	failedRuns     float64
	successfulRuns float64
}

func newGC(
	params gcParams,
) *GC {
	if !params.Clientset.IsEnabled() {
		return nil
	}

	obj := &GC{
		logger:           params.Logger,
		clientset:        params.Clientset.CiliumV2().CiliumIdentities(),
		identity:         params.Identity,
		allocationMode:   params.SharedCfg.IdentityAllocationMode,
		gcInterval:       params.Cfg.GCInterval,
		heartbeatTimeout: params.Cfg.HeartbeatTimeout,
		gcRateInterval:   params.Cfg.GCRateInterval,
		gcRateLimit:      params.Cfg.GCRateLimit,
		wp:               workerpool.New(1),
		heartbeatStore: newHeartbeatStore(
			params.Cfg.HeartbeatTimeout,
		),
		rateLimiter: rate.NewLimiter(
			params.Cfg.GCRateInterval,
			params.Cfg.GCRateLimit,
		),
		allocationCfg: identityAllocationConfig{
			clusterName:  params.SharedCfg.ClusterName,
			k8sNamespace: params.SharedCfg.K8sNamespace,
			clusterID:    params.SharedCfg.ClusterID,
		},
	}
	params.Lifecycle.Append(obj)

	return obj
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
