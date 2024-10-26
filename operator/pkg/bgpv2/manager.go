// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/util/wait"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// retry options used in reconcileWithRetry method.
	// steps will repeat for ~8.5 minutes.
	bo = wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Jitter:   0,
		Steps:    10,
		Cap:      0,
	}

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

	// resource tracking
	ClusterConfigResource      resource.Resource[*cilium_api_v2alpha1.CiliumBGPClusterConfig]
	NodeConfigOverrideResource resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride]
	NodeConfigResource         resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfig]
	PeerConfigResource         resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeerConfig]
	NodeResource               resource.Resource[*cilium_api_v2.CiliumNode]
}

type BGPResourceManager struct {
	logger    *slog.Logger
	clientset k8s_client.Clientset
	lc        cell.Lifecycle
	jobs      job.Group
	health    cell.Health

	// For BGP Cluster Config
	clusterConfig           resource.Resource[*cilium_api_v2alpha1.CiliumBGPClusterConfig]
	nodeConfigOverride      resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride]
	nodeConfig              resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfig]
	ciliumNode              resource.Resource[*cilium_api_v2.CiliumNode]
	peerConfig              resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeerConfig]
	clusterConfigStore      resource.Store[*cilium_api_v2alpha1.CiliumBGPClusterConfig]
	nodeConfigOverrideStore resource.Store[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride]
	nodeConfigStore         resource.Store[*cilium_api_v2alpha1.CiliumBGPNodeConfig]
	peerConfigStore         resource.Store[*cilium_api_v2alpha1.CiliumBGPPeerConfig]
	ciliumNodeStore         resource.Store[*cilium_api_v2.CiliumNode]
	nodeConfigClient        cilium_client_v2alpha1.CiliumBGPNodeConfigInterface

	// internal state
	reconcileCh      chan struct{}
	bgpClusterSyncCh chan struct{}
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

		reconcileCh:        make(chan struct{}, 1),
		bgpClusterSyncCh:   make(chan struct{}, 1),
		clusterConfig:      p.ClusterConfigResource,
		nodeConfigOverride: p.NodeConfigOverrideResource,
		nodeConfig:         p.NodeConfigResource,
		peerConfig:         p.PeerConfigResource,
		ciliumNode:         p.NodeResource,
	}

	b.nodeConfigClient = b.clientset.CiliumV2alpha1().CiliumBGPNodeConfigs()

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
	retryFn := func(ctx context.Context) (bool, error) {
		err := b.reconcile(ctx)

		switch {
		case err != nil:
			// log error, continue retry
			b.logger.Warn("BGP reconciliation error", logfields.Error, TrimError(err, maxErrorLen))
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
