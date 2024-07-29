// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// clusterMesh is a cache of multiple remote clusters
type clusterMesh struct {
	// common implements the common logic to connect to remote clusters.
	common common.ClusterMesh

	cfg       ClusterMeshConfig
	cfgMCSAPI MCSAPIConfig
	logger    logrus.FieldLogger
	Metrics   Metrics

	// globalServices is a list of all global services. The datastructure
	// is protected by its own mutex inside the structure.
	globalServices *common.GlobalServiceCache

	storeFactory store.Factory

	started                   atomic.Bool
	clusterAddHooks           []func(string)
	clusterDeleteHooks        []func(string)
	clusterServiceUpdateHooks []func(*serviceStore.ClusterService)
	clusterServiceDeleteHooks []func(*serviceStore.ClusterService)

	syncTimeoutConfig  wait.TimeoutConfig
	syncTimeoutLogOnce sync.Once
}

// ClusterMesh is the interface corresponding to the clusterMesh struct to expose
// its public methods to other Cilium packages.
type ClusterMesh interface {
	// RegisterClusterAddHook register a hook when a cluster is added to the mesh.
	// This should NOT be called after the Start hook.
	RegisterClusterAddHook(clusterAddHook func(string))
	// RegisterClusterDeleteHook register a hook when a cluster is removed from the mesh.
	// This should NOT be called after the Start hook.
	RegisterClusterDeleteHook(clusterDeleteHook func(string))
	// RegisterClusterServiceUpdateHook register a hook when a service in the mesh is updated.
	// This should NOT be called after the Start hook.
	RegisterClusterServiceUpdateHook(clusterServiceUpdateHook func(*serviceStore.ClusterService))
	// RegisterClusterServiceDeleteHook register a hook when a service in the mesh is deleted.
	// This should NOT be called after the Start hook.
	RegisterClusterServiceDeleteHook(clusterServiceDeleteHook func(*serviceStore.ClusterService))

	ServicesSynced(ctx context.Context) error
	GlobalServices() *common.GlobalServiceCache
}

func newClusterMesh(lc cell.Lifecycle, params clusterMeshParams) (*clusterMesh, ClusterMesh) {
	if params.ClusterInfo.ID == 0 || params.ClusterMeshConfig == "" {
		return nil, nil
	}

	if !params.Cfg.ClusterMeshEnableEndpointSync && !params.CfgMCSAPI.ClusterMeshEnableMCSAPI {
		return nil, nil
	}

	params.Logger.Info("Operator ClusterMesh component enabled")

	cm := clusterMesh{
		cfg:       params.Cfg,
		cfgMCSAPI: params.CfgMCSAPI,
		logger:    params.Logger,
		globalServices: common.NewGlobalServiceCache(
			params.Metrics.TotalGlobalServices.WithLabelValues(params.ClusterInfo.Name),
		),
		storeFactory:      params.StoreFactory,
		syncTimeoutConfig: params.TimeoutConfig,
	}
	cm.common = common.NewClusterMesh(common.Configuration{
		Config:           params.Config,
		ClusterInfo:      params.ClusterInfo,
		NewRemoteCluster: cm.newRemoteCluster,
		ServiceResolver:  params.ServiceResolver,
		Metrics:          params.CommonMetrics,
	})

	lc.Append(cm.common)
	lc.Append(&cm)
	return &cm, &cm
}

// RegisterClusterAddHook register a hook when a cluster is added to the mesh.
// This should NOT be called after the Start hook.
func (cm *clusterMesh) RegisterClusterAddHook(clusterAddHook func(string)) {
	if cm.started.Load() {
		panic(fmt.Errorf("can't call RegisterClusterAddHook after the Start hook"))
	}
	cm.clusterAddHooks = append(cm.clusterAddHooks, clusterAddHook)
}

// RegisterClusterDeleteHook register a hook when a cluster is removed from the mesh.
// This should NOT be called after the Start hook.
func (cm *clusterMesh) RegisterClusterDeleteHook(clusterDeleteHook func(string)) {
	if cm.started.Load() {
		panic(fmt.Errorf("can't call RegisterClusterDeleteHook after the Start hook"))
	}
	cm.clusterDeleteHooks = append(cm.clusterDeleteHooks, clusterDeleteHook)
}

// RegisterClusterServiceUpdateHook register a hook when a service in the mesh is updated.
// This should NOT be called after the Start hook.
func (cm *clusterMesh) RegisterClusterServiceUpdateHook(clusterServiceUpdateHook func(*serviceStore.ClusterService)) {
	if cm.started.Load() {
		panic(fmt.Errorf("can't call RegisterClusterServiceUpdateHook after the Start hook"))
	}
	cm.clusterServiceUpdateHooks = append(cm.clusterServiceUpdateHooks, clusterServiceUpdateHook)
}

// RegisterClusterServiceDeleteHook register a hook when a service in the mesh is deleted.
// This should NOT be called after the Start hook.
func (cm *clusterMesh) RegisterClusterServiceDeleteHook(clusterServiceDeleteHook func(*serviceStore.ClusterService)) {
	if cm.started.Load() {
		panic(fmt.Errorf("can't call RegisterClusterServiceDeleteHook after the Start hook"))
	}
	cm.clusterServiceDeleteHooks = append(cm.clusterServiceDeleteHooks, clusterServiceDeleteHook)
}

func (cm *clusterMesh) GlobalServices() *common.GlobalServiceCache {
	return cm.globalServices
}

func (cm *clusterMesh) newRemoteCluster(name string, status common.StatusFunc) common.RemoteCluster {
	rc := &remoteCluster{
		name:                          name,
		clusterMeshEnableEndpointSync: cm.cfg.ClusterMeshEnableEndpointSync,
		clusterMeshEnableMCSAPI:       cm.cfgMCSAPI.ClusterMeshEnableMCSAPI,
		globalServices:                cm.globalServices,
		storeFactory:                  cm.storeFactory,
		synced:                        newSynced(),
		status:                        status,
		clusterAddHooks:               cm.clusterAddHooks,
		clusterDeleteHooks:            cm.clusterDeleteHooks,
	}

	rc.remoteServices = cm.storeFactory.NewWatchStore(
		name,
		serviceStore.KeyCreator(
			serviceStore.ClusterNameValidator(name),
			serviceStore.NamespacedNameValidator(),
		),
		common.NewSharedServicesObserver(
			cm.logger.WithField(logfields.ClusterName, name),
			cm.globalServices,
			func(svc *serviceStore.ClusterService) {
				for _, hook := range cm.clusterServiceUpdateHooks {
					hook(svc)
				}
			},
			func(svc *serviceStore.ClusterService) {
				for _, hook := range cm.clusterServiceDeleteHooks {
					hook(svc)
				}
			},
		),
		store.RWSWithOnSyncCallback(func(ctx context.Context) { rc.synced.services.Stop() }),
	)

	return rc
}

func (cm *clusterMesh) Start(cell.HookContext) error {
	cm.started.Store(true)
	return nil
}

func (cm *clusterMesh) Stop(cell.HookContext) error {
	return nil
}

// ServicesSynced returns after that either the initial list of shared services has
// been received from all remote clusters, or the maximum wait period controlled by the
// clustermesh-sync-timeout flag elapsed. It returns an error if the given context expired.
func (cm *clusterMesh) ServicesSynced(ctx context.Context) error {
	return cm.synced(ctx, func(rc *remoteCluster) wait.Fn { return rc.synced.Services })
}

func (cm *clusterMesh) synced(ctx context.Context, toWaitFn func(*remoteCluster) wait.Fn) error {
	wctx, cancel := context.WithTimeout(ctx, cm.syncTimeoutConfig.ClusterMeshSyncTimeout)
	defer cancel()

	waiters := make([]wait.Fn, 0)
	cm.common.ForEachRemoteCluster(func(rci common.RemoteCluster) error {
		rc := rci.(*remoteCluster)
		waiters = append(waiters, toWaitFn(rc))
		return nil
	})

	err := wait.ForAll(wctx, waiters)
	if ctx.Err() == nil && wctx.Err() != nil {
		// The sync timeout expired, but the parent context is still valid, which
		// means that the circuit breaker was triggered. Print a warning message
		// and continue normally, as if the synchronization completed successfully.
		// This ensures that we don't block forever in case of misconfigurations.
		cm.syncTimeoutLogOnce.Do(func() {
			cm.logger.Warning("Failed waiting for clustermesh synchronization, expect possible disruption of cross-cluster connections")
		})

		return nil
	}

	return err
}

// Status returns the status of the ClusterMesh subsystem
func (cm *clusterMesh) status() []*models.RemoteCluster {
	var clusters []*models.RemoteCluster

	cm.common.ForEachRemoteCluster(func(rci common.RemoteCluster) error {
		rc := rci.(*remoteCluster)
		clusters = append(clusters, rc.Status())
		return nil
	})

	// Sort the remote clusters information to ensure consistent ordering.
	slices.SortFunc(clusters,
		func(a, b *models.RemoteCluster) int { return cmp.Compare(a.Name, b.Name) })

	return clusters
}
