// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

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
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// maxErrorLen is the maximum length of error message to be logged.
const maxErrorLen = 140

// VTEPParams contains the dependencies injected into the VTEP operator controller.
type VTEPParams struct {
	cell.In

	Logger       *slog.Logger
	LC           cell.Lifecycle
	Clientset    k8s_client.Clientset
	DaemonConfig *option.DaemonConfig
	JobGroup     job.Group
	Health       cell.Health

	ClusterConfigResource resource.Resource[*v2alpha1.CiliumVTEPConfig]
	NodeConfigResource    resource.Resource[*v2alpha1.CiliumVTEPNodeConfig]
	NodeResource          resource.Resource[*v2.CiliumNode]
}

// VTEPResourceManager resolves CiliumVTEPConfig objects into per-node
// CiliumVTEPNodeConfig objects.
type VTEPResourceManager struct {
	logger    *slog.Logger
	clientset k8s_client.Clientset
	jobs      job.Group
	health    cell.Health

	clusterConfig resource.Resource[*v2alpha1.CiliumVTEPConfig]
	nodeConfig    resource.Resource[*v2alpha1.CiliumVTEPNodeConfig]
	ciliumNode    resource.Resource[*v2.CiliumNode]

	clusterConfigStore resource.Store[*v2alpha1.CiliumVTEPConfig]
	nodeConfigStore    resource.Store[*v2alpha1.CiliumVTEPNodeConfig]
	ciliumNodeStore    resource.Store[*v2.CiliumNode]

	nodeConfigClient cilium_client_v2alpha1.CiliumVTEPNodeConfigInterface

	reconcileCh chan struct{}
	syncCh      chan struct{}
}

// registerVTEPResourceManager creates and registers the VTEP operator controller.
func registerVTEPResourceManager(p VTEPParams) *VTEPResourceManager {
	if !p.Clientset.IsEnabled() || !p.DaemonConfig.EnableVTEP {
		return nil
	}

	m := &VTEPResourceManager{
		logger:        p.Logger,
		clientset:     p.Clientset,
		jobs:          p.JobGroup,
		health:        p.Health,
		clusterConfig: p.ClusterConfigResource,
		nodeConfig:    p.NodeConfigResource,
		ciliumNode:    p.NodeResource,
		reconcileCh:   make(chan struct{}, 1),
		syncCh:        make(chan struct{}, 1),
	}
	m.nodeConfigClient = p.Clientset.CiliumV2alpha1().CiliumVTEPNodeConfigs()

	m.initializeJobs()

	return m
}

func (m *VTEPResourceManager) initializeJobs() {
	m.jobs.Add(
		job.OneShot("vtep-operator-main", func(ctx context.Context, health cell.Health) error {
			if err := m.initializeStores(ctx); err != nil {
				return err
			}
			m.logger.Info("VTEP operator started")
			return m.Run(ctx)
		}),

		job.OneShot("vtep-operator-cluster-config-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range m.clusterConfig.Events(ctx) {
				if e.Kind == resource.Sync {
					select {
					case m.syncCh <- struct{}{}:
					default:
					}
				}
				m.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("vtep-operator-node-config-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range m.nodeConfig.Events(ctx) {
				m.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("vtep-operator-node-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range m.ciliumNode.Events(ctx) {
				m.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),
	)
}

func (m *VTEPResourceManager) initializeStores(ctx context.Context) (err error) {
	if m.clusterConfigStore, err = m.clusterConfig.Store(ctx); err != nil {
		return err
	}
	if m.nodeConfigStore, err = m.nodeConfig.Store(ctx); err != nil {
		return err
	}
	if m.ciliumNodeStore, err = m.ciliumNode.Store(ctx); err != nil {
		return err
	}
	return nil
}

// triggerReconcile initiates a level-triggered reconciliation.
func (m *VTEPResourceManager) triggerReconcile() {
	select {
	case m.reconcileCh <- struct{}{}:
		m.logger.Debug("VTEP reconciliation triggered")
	default:
	}
}

// Run starts the reconciliation loop after the cluster config has synced.
func (m *VTEPResourceManager) Run(ctx context.Context) error {
	// Wait for the cluster config to sync before the first reconcile.
	select {
	case <-ctx.Done():
		return nil
	case <-m.syncCh:
	}

	m.triggerReconcile()

	for {
		select {
		case <-ctx.Done():
			return nil
		case _, open := <-m.reconcileCh:
			if !open {
				return nil
			}
			if err := m.reconcileWithRetry(ctx); err != nil {
				m.logger.ErrorContext(ctx, "VTEP reconciliation failed", logfields.Error, err)
			} else {
				m.logger.DebugContext(ctx, "VTEP reconciliation successful")
			}
		}
	}
}

// reconcileWithRetry retries reconcile with exponential backoff.
func (m *VTEPResourceManager) reconcileWithRetry(ctx context.Context) error {
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
		err := m.reconcile(ctx)
		switch {
		case err != nil:
			if isRetryableError(err) && attempt%5 != 0 {
				m.logger.DebugContext(ctx, "Transient VTEP reconciliation error", logfields.Error, trimError(err, maxErrorLen))
			} else {
				m.logger.WarnContext(ctx, "VTEP reconciliation error", logfields.Error, trimError(err, maxErrorLen))
			}
			return false, nil
		default:
			return true, nil
		}
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, retryFn)
}

// trimError trims an error message to maxLen.
func trimError(err error, maxLen int) error {
	if err == nil {
		return nil
	}
	if len(err.Error()) > maxLen {
		return fmt.Errorf("%s... ", err.Error()[:maxLen])
	}
	return err
}

// isRetryableError returns true if the reconcile error is likely transient.
func isRetryableError(err error) bool {
	return k8serrors.IsAlreadyExists(err) ||
		k8serrors.IsConflict(err) ||
		k8serrors.IsNotFound(err) ||
		(k8serrors.IsForbidden(err) && k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause))
}
