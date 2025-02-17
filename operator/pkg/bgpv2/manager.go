// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// maxErrorLen is the maximum length of error message to be logged.
	maxErrorLen = 140
)

type BGPParams struct {
	cell.In

	Logger       *slog.Logger
	LC           cell.Lifecycle
	Clientset    k8s_client.Clientset
	DaemonConfig *option.DaemonConfig
	JobGroup     job.Group
	Health       cell.Health
	Metrics      *BGPOperatorMetrics

	// resource tracking
	ClusterConfigResource      resource.Resource[*v2.CiliumBGPClusterConfig]
	NodeConfigOverrideResource resource.Resource[*v2.CiliumBGPNodeConfigOverride]
	NodeConfigResource         resource.Resource[*v2.CiliumBGPNodeConfig]
	PeerConfigResource         resource.Resource[*v2.CiliumBGPPeerConfig]
	NodeResource               resource.Resource[*v2.CiliumNode]
}

type BGPResourceManager struct {
	logger    *slog.Logger
	clientset k8s_client.Clientset
	lc        cell.Lifecycle
	jobs      job.Group
	health    cell.Health
	metrics   *BGPOperatorMetrics

	// For BGP Cluster Config
	clusterConfig           resource.Resource[*v2.CiliumBGPClusterConfig]
	nodeConfigOverride      resource.Resource[*v2.CiliumBGPNodeConfigOverride]
	nodeConfig              resource.Resource[*v2.CiliumBGPNodeConfig]
	ciliumNode              resource.Resource[*v2.CiliumNode]
	peerConfig              resource.Resource[*v2.CiliumBGPPeerConfig]
	clusterConfigStore      resource.Store[*v2.CiliumBGPClusterConfig]
	nodeConfigOverrideStore resource.Store[*v2.CiliumBGPNodeConfigOverride]
	nodeConfigStore         resource.Store[*v2.CiliumBGPNodeConfig]
	peerConfigStore         resource.Store[*v2.CiliumBGPPeerConfig]
	ciliumNodeStore         resource.Store[*v2.CiliumNode]
	nodeConfigClient        cilium_client_v2.CiliumBGPNodeConfigInterface

	// internal state
	reconcileCh      chan struct{}
	bgpClusterSyncCh chan struct{}

	// enable/disable status reporting
	enableStatusReporting bool
}

// registerBGPResourceManager creates a new BGPResourceManager operator instance.
func registerBGPResourceManager(p BGPParams) *BGPResourceManager {
	// if BGPResourceManager Control Plane is not enabled or BGPv2 API is not enabled, return nil
	if !p.DaemonConfig.BGPControlPlaneEnabled() {
		return nil
	}

	b := &BGPResourceManager{
		logger:    p.Logger,
		clientset: p.Clientset,
		jobs:      p.JobGroup,
		lc:        p.LC,
		health:    p.Health,
		metrics:   p.Metrics,

		reconcileCh:        make(chan struct{}, 1),
		bgpClusterSyncCh:   make(chan struct{}, 1),
		clusterConfig:      p.ClusterConfigResource,
		nodeConfigOverride: p.NodeConfigOverrideResource,
		nodeConfig:         p.NodeConfigResource,
		peerConfig:         p.PeerConfigResource,
		ciliumNode:         p.NodeResource,

		enableStatusReporting: p.DaemonConfig.EnableBGPControlPlaneStatusReport,
	}

	b.nodeConfigClient = b.clientset.CiliumV2().CiliumBGPNodeConfigs()

	// initialize jobs and register them with lifecycle
	b.initializeJobs()

	return b
}

func (b *BGPResourceManager) initializeJobs() {
	b.jobs.Add(
		job.OneShot("bgpv2-operator-main", func(ctx context.Context, health cell.Health) error {
			// initialize resource stores
			err := b.initializeStores(ctx)
			if err != nil {
				return err
			}

			b.logger.Info("BGPv2 control plane operator started")

			return b.Run(ctx)
		}),

		job.OneShot("bgpv2-operator-cluster-config-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range b.clusterConfig.Events(ctx) {
				if e.Kind == resource.Sync {
					select {
					case b.bgpClusterSyncCh <- struct{}{}:
					default:
					}
				}

				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgpv2-operator-node-config-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range b.nodeConfig.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgpv2-operator-node-config-override-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range b.nodeConfigOverride.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgpv2-operator-peer-config-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range b.peerConfig.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgpv2-operator-node-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range b.ciliumNode.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),
	)
}

func (b *BGPResourceManager) initializeStores(ctx context.Context) (err error) {
	b.clusterConfigStore, err = b.clusterConfig.Store(ctx)
	if err != nil {
		return
	}

	b.nodeConfigOverrideStore, err = b.nodeConfigOverride.Store(ctx)
	if err != nil {
		return
	}

	b.nodeConfigStore, err = b.nodeConfig.Store(ctx)
	if err != nil {
		return
	}

	b.peerConfigStore, err = b.peerConfig.Store(ctx)
	if err != nil {
		return
	}

	b.ciliumNodeStore, err = b.ciliumNode.Store(ctx)
	if err != nil {
		return
	}

	return nil
}

// triggerReconcile initiates level triggered reconciliation.
func (b *BGPResourceManager) triggerReconcile() {
	select {
	case b.reconcileCh <- struct{}{}:
		b.logger.Debug("BGP reconciliation triggered")
	default:
	}
}

// Run starts the BGPResourceManager operator.
func (b *BGPResourceManager) Run(ctx context.Context) (err error) {
	// make sure cluster config is synced before starting the reconciliation
	<-b.bgpClusterSyncCh

	// trigger reconciliation for first time.
	b.triggerReconcile()

	for {
		select {
		case <-ctx.Done():
			return

		case _, open := <-b.reconcileCh:
			if !open {
				return
			}

			err := b.reconcileWithRetry(ctx)
			if err != nil {
				b.logger.Error("BGP reconciliation failed", logfields.Error, err)
			} else {
				b.logger.Debug("BGP reconciliation successful")
			}
		}
	}
}

// reconcileWithRetry retries reconcile with exponential backoff.
func (b *BGPResourceManager) reconcileWithRetry(ctx context.Context) error {
	// steps will repeat for ~8.5 minutes.
	bo := wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   0,
		Steps:    10,
		Cap:      0,
	}
	attempt := 0

	retryFn := func(ctx context.Context) (bool, error) {
		attempt++

		err := b.reconcile(ctx)

		switch {
		case err != nil:
			// log error, continue retry
			if isRetryableError(err) && attempt%5 != 0 {
				// for retryable error print warning only every 5th attempt
				b.logger.Debug("Transient BGP reconciliation error", logfields.Error, TrimError(err, maxErrorLen))
			} else {
				b.logger.Warn("BGP reconciliation error", logfields.Error, TrimError(err, maxErrorLen))
			}
			return false, nil
		default:
			// no error, stop retry
			return true, nil
		}
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, retryFn)
}

// reconcile is called when any interesting resource change event is triggered.
func (b *BGPResourceManager) reconcile(ctx context.Context) error {
	return b.reconcileBGPClusterConfigs(ctx)
}

// TrimError trims error message to maxLen.
func TrimError(err error, maxLen int) error {
	if err == nil {
		return nil
	}

	if len(err.Error()) > maxLen {
		return fmt.Errorf("%s... ", err.Error()[:maxLen])
	}
	return err
}

// isRetryableError returns true if the error returned by reconcile
// is likely transient, and will be addressed by a subsequent iteration.
func isRetryableError(err error) bool {
	return k8serrors.IsAlreadyExists(err) ||
		k8serrors.IsConflict(err) ||
		k8serrors.IsNotFound(err) ||
		(k8serrors.IsForbidden(err) && k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause))
}
