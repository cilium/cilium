// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/operator/pkg/lbipam"
	"github.com/cilium/cilium/pkg/ipalloc"
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
	AdvertisementResource      resource.Resource[*v2.CiliumBGPAdvertisement]
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
	advertisement           resource.Resource[*v2.CiliumBGPAdvertisement]
	clusterConfigStore      resource.Store[*v2.CiliumBGPClusterConfig]
	nodeConfigOverrideStore resource.Store[*v2.CiliumBGPNodeConfigOverride]
	nodeConfigStore         resource.Store[*v2.CiliumBGPNodeConfig]
	peerConfigStore         resource.Store[*v2.CiliumBGPPeerConfig]
	advertisementStore      resource.Store[*v2.CiliumBGPAdvertisement]
	ciliumNodeStore         resource.Store[*v2.CiliumNode]
	nodeConfigClient        cilium_client_v2.CiliumBGPNodeConfigInterface

	// internal state
	reconcileCh       chan struct{}
	bgpClusterSyncCh  chan struct{}
	storesInitialized chan struct{}

	// enable/disable status reporting
	enableStatusReporting bool

	// bgp routerID allocation through the ip pool
	bgpRouterIDIPPoolEnabled bool
	bgpRouterIDIPPool        *ipalloc.HashAllocator[string]
	bgpRouterIDMap           map[string]*netip.Addr
}

// Interface to use during version migration
type listPatcher interface {
	List() []string
	Patch(context.Context, string, k8s_types.PatchType, []byte, metav1.PatchOptions, ...string) (any, error)
}

// Wrapper around resource.Store and cilium_client_v2.CiliumBGP*Interface
type resourceClient[T metav1.Object] struct {
	lister  func() []T
	patcher func(context.Context, string, k8s_types.PatchType, []byte, metav1.PatchOptions, ...string) (T, error)
}

func (r resourceClient[T]) List() []string {
	names := []string{}
	for _, item := range r.lister() {
		names = append(names, item.GetName())
	}

	return names
}

func (r resourceClient[T]) Patch(ctx context.Context, name string, pt k8s_types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (any, error) {
	return r.patcher(ctx, name, pt, data, opts, subresources...)
}

// registerBGPResourceManager creates a new BGPResourceManager operator instance.
func registerBGPResourceManager(p BGPParams) *BGPResourceManager {
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

		reconcileCh:           make(chan struct{}, 1),
		bgpClusterSyncCh:      make(chan struct{}, 1),
		storesInitialized:     make(chan struct{}, 1),
		bgpRouterIDMap:        make(map[string]*netip.Addr),
		clusterConfig:         p.ClusterConfigResource,
		nodeConfigOverride:    p.NodeConfigOverrideResource,
		nodeConfig:            p.NodeConfigResource,
		peerConfig:            p.PeerConfigResource,
		advertisement:         p.AdvertisementResource,
		ciliumNode:            p.NodeResource,
		enableStatusReporting: p.DaemonConfig.EnableBGPControlPlaneStatusReport,
	}
	if p.DaemonConfig.BGPRouterIDAllocationMode == option.BGPRouterIDAllocationModeIPPool {
		ipnet, err := netip.ParsePrefix(p.DaemonConfig.BGPRouterIDAllocationIPPool)
		if err != nil {
			err = fmt.Errorf("failed to parse BGP router ID IP pool: %w", err)
			b.logger.Error(err.Error())
			b.health.Degraded("BGP manager health degraded", err)
		}
		if !ipnet.Addr().Is4() {
			err = fmt.Errorf("BGP router ID IP pool is not an IPv4 CIDR")
			b.logger.Error(err.Error())
			b.health.Degraded("BGP manager health degraded", err)
		}

		from, to := lbipam.RangeFromPrefix(ipnet)
		// 50 router IDs as the initial size is enough for hash map since we don't expect more than too many nodes
		//to run BGP with upstream routers and it can still grow if needed.
		b.bgpRouterIDIPPool, err = ipalloc.NewHashAllocator[string](from, to, 50)
		if err != nil {
			err = fmt.Errorf("failed to create router ID IP pool: %w", err)
			b.logger.Error(err.Error())
			b.health.Degraded("BGP manager health degraded", err)
		}
		b.bgpRouterIDIPPoolEnabled = true
	}
	b.nodeConfigClient = b.clientset.CiliumV2().CiliumBGPNodeConfigs()
	// initialize jobs and register them with lifecycle
	b.initializeJobs()

	return b
}

func (b *BGPResourceManager) initializeJobs() {
	b.jobs.Add(
		job.OneShot("bgp-operator-main", func(ctx context.Context, health cell.Health) error {
			// initialize resource stores
			err := b.initializeStores(ctx)
			if err != nil {
				return err
			}

			b.logger.Info("BGP control plane operator started")
			// restore router IDs for all nodes
			if err := b.restoreRouterIDs(); err != nil {
				return err
			}

			b.storesInitialized <- struct{}{}

			return b.Run(ctx)
		}),

		job.OneShot("bgp-operator-cluster-config-tracker", func(ctx context.Context, health cell.Health) error {
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

		job.OneShot("bgp-operator-node-config-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range b.nodeConfig.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgp-operator-node-config-override-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range b.nodeConfigOverride.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgp-operator-peer-config-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range b.peerConfig.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgp-operator-node-tracker", func(ctx context.Context, health cell.Health) error {
			for e := range b.ciliumNode.Events(ctx) {
				b.triggerReconcile()
				e.Done(nil)
			}
			return nil
		}),

		// If the storedVersion contains v2alpha1 then etcd probably contains BGP resource as v2alpha1.
		// This can prevent deleting the v2alpha1.
		// The solution is to add an empty patch to the resource so etcd force to update and store it with the new version.
		// After that we can delete the v2alpha1 from the storedVersion.
		job.OneShot("bgp-operator-crd-storage-version-migrator", func(ctx context.Context, health cell.Health) error {
			<-b.storesInitialized

			crdClient := b.clientset.ApiextensionsV1().CustomResourceDefinitions()
			resourceClients := map[string]listPatcher{
				"ciliumbgpclusterconfigs.cilium.io": resourceClient[*v2.CiliumBGPClusterConfig]{
					lister:  b.clusterConfigStore.List,
					patcher: b.clientset.CiliumV2().CiliumBGPClusterConfigs().Patch,
				},
				"ciliumbgppeerconfigs.cilium.io": resourceClient[*v2.CiliumBGPPeerConfig]{
					lister:  b.peerConfigStore.List,
					patcher: b.clientset.CiliumV2().CiliumBGPPeerConfigs().Patch,
				},
				"ciliumbgpadvertisements.cilium.io": resourceClient[*v2.CiliumBGPAdvertisement]{
					lister:  b.advertisementStore.List,
					patcher: b.clientset.CiliumV2().CiliumBGPAdvertisements().Patch,
				},
				"ciliumbgpnodeconfigs.cilium.io": resourceClient[*v2.CiliumBGPNodeConfig]{
					lister:  b.nodeConfigStore.List,
					patcher: b.clientset.CiliumV2().CiliumBGPNodeConfigs().Patch,
				},
				"ciliumbgpnodeconfigoverrides.cilium.io": resourceClient[*v2.CiliumBGPNodeConfigOverride]{
					lister:  b.nodeConfigOverrideStore.List,
					patcher: b.clientset.CiliumV2().CiliumBGPNodeConfigOverrides().Patch,
				},
			}
			versionFromMigrate := "v2alpha1"

			for crdName, client := range resourceClients {
				migrated, err := storageVersionMigrator(ctx, crdClient, crdName, client, versionFromMigrate)

				if err != nil {
					return err
				}

				if migrated {
					b.logger.Debug("CRD migrated", logfields.ResourceName, crdName)
				}
			}

			return nil
		}, job.WithRetry(3, &job.ExponentialBackoff{Min: 500 * time.Millisecond, Max: 3 * time.Second})),
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

	b.advertisementStore, err = b.advertisement.Store(ctx)
	if err != nil {
		return
	}

	b.ciliumNodeStore, err = b.ciliumNode.Store(ctx)
	if err != nil {
		return
	}

	return nil
}

func storageVersionMigrator(ctx context.Context, crdClient v1.CustomResourceDefinitionInterface, crdName string, client listPatcher, versionFromMigrate string) (bool, error) {
	crdDef, err := crdClient.Get(ctx, crdName, metav1.GetOptions{})

	if err != nil {
		return false, err
	}

	if slices.Contains(crdDef.Status.StoredVersions, versionFromMigrate) {
		for _, name := range client.List() {
			if _, err := client.Patch(ctx, name, k8s_types.MergePatchType, []byte("{}"), metav1.PatchOptions{}); err != nil {
				return false, err
			}
		}

		storedVersions := slices.DeleteFunc(crdDef.Status.StoredVersions, func(s string) bool {
			return s == versionFromMigrate
		})
		crdDef.Status.StoredVersions = storedVersions
		if _, err := crdClient.UpdateStatus(ctx, crdDef, metav1.UpdateOptions{}); err != nil {
			return false, err
		}

		return true, nil
	}

	return false, nil
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
				b.logger.ErrorContext(ctx, "BGP reconciliation failed", logfields.Error, err)
			} else {
				b.logger.DebugContext(ctx, "BGP reconciliation successful")
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
				b.logger.DebugContext(ctx, "Transient BGP reconciliation error", logfields.Error, TrimError(err, maxErrorLen))
			} else {
				b.logger.WarnContext(ctx, "BGP reconciliation error", logfields.Error, TrimError(err, maxErrorLen))
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
	reconcileStart := time.Now()

	err := b.reconcileBGPClusterConfigs(ctx)

	b.metrics.ReconcileRunDuration.WithLabelValues().Observe(time.Since(reconcileStart).Seconds())
	return err
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
