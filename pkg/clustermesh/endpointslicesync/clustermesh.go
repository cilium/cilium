// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync/atomic"

	"github.com/cilium/endpointslice-controller/endpointslice"
	"github.com/cilium/hive/cell"
	"k8s.io/client-go/informers"
	cache "k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/loadbalancer"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// clusterMesh is a cache of multiple remote clusters
type clusterMesh struct {
	// common implements the common logic to connect to remote clusters.
	common common.ClusterMesh

	context       context.Context
	contextCancel context.CancelFunc
	Metrics       Metrics

	// globalServices is a list of all global services. The datastructure
	// is protected by its own mutex inside the structure.
	globalServices *common.GlobalServiceCache

	storeFactory store.Factory

	concurrentClusterMeshEndpointSync int

	meshPodInformer     *meshPodInformer
	meshNodeInformer    *meshNodeInformer
	meshServiceInformer *meshServiceInformer

	endpointSliceMeshController  *endpointslice.Controller
	endpointSliceInformerFactory informers.SharedInformerFactory

	started                   atomic.Bool
	clusterAddHooks           []func(string)
	clusterDeleteHooks        []func(string)
	clusterServiceUpdateHooks []func(*serviceStore.ClusterService)
	clusterServiceDeleteHooks []func(*serviceStore.ClusterService)
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
	if !params.Clientset.IsEnabled() || params.ClusterMeshConfig == "" || !params.Cfg.ClusterMeshEnableEndpointSync {
		return nil, nil
	}

	log.Info("Endpoint Slice Cluster Mesh synchronization enabled")

	cm := clusterMesh{
		Metrics: params.Metrics,
		globalServices: common.NewGlobalServiceCache(
			params.Metrics.TotalGlobalServices.WithLabelValues(params.ClusterInfo.Name),
		),
		storeFactory:                      params.StoreFactory,
		concurrentClusterMeshEndpointSync: params.Cfg.ClusterMeshMaxEndpointsPerSlice,
	}
	cm.context, cm.contextCancel = context.WithCancel(context.Background())
	cm.meshPodInformer = newMeshPodInformer(cm.globalServices)
	cm.RegisterClusterServiceUpdateHook(cm.meshPodInformer.onClusterServiceUpdate)
	cm.RegisterClusterServiceDeleteHook(cm.meshPodInformer.onClusterServiceDelete)
	cm.meshNodeInformer = newMeshNodeInformer()
	cm.RegisterClusterAddHook(cm.meshNodeInformer.onClusterAdd)
	cm.RegisterClusterDeleteHook(cm.meshNodeInformer.onClusterDelete)
	cm.endpointSliceMeshController, cm.meshServiceInformer, cm.endpointSliceInformerFactory = newEndpointSliceMeshController(
		cm.context, params.Cfg, cm.meshPodInformer,
		cm.meshNodeInformer, params.Clientset,
		params.Services, cm.globalServices,
	)
	cm.common = common.NewClusterMesh(common.Configuration{
		Config:           params.Config,
		ClusterInfo:      params.ClusterInfo,
		NewRemoteCluster: cm.newRemoteCluster,
		ServiceIPGetter:  &clusterMeshServiceGetter{services: params.Services},
		Metrics:          params.CommonMetrics,
	})

	lc.Append(cm.common)
	lc.Append(&cm)
	return &cm, &cm
}

// clusterMeshServiceGetter relies on resource.Resource[*slim_corev1.Service]
// to get the service for the remote clusters.
type clusterMeshServiceGetter struct {
	services resource.Resource[*slim_corev1.Service]
	store    resource.Store[*slim_corev1.Service]
}

func (cm *clusterMeshServiceGetter) initStore() error {
	var err error
	if cm.store == nil {
		cm.store, err = cm.services.Store(context.Background())
		if err != nil {
			return err
		}
	}
	return nil
}

func (cm *clusterMeshServiceGetter) GetServiceIP(svcID k8s.ServiceID) *loadbalancer.L3n4Addr {
	if cm.initStore() != nil {
		return nil
	}

	svc, exists, err := cm.store.GetByKey(resource.Key{Name: svcID.Name, Namespace: svcID.Namespace})
	if !exists || err != nil {
		return nil
	}

	for _, port := range svc.Spec.Ports {
		return loadbalancer.NewL3n4Addr(
			string(port.Protocol),
			cmtypes.MustAddrClusterFromIP(net.ParseIP(svc.Spec.ClusterIP)),
			uint16(port.Port),
			loadbalancer.ScopeExternal,
		)
	}
	return nil
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
		name:               name,
		globalServices:     cm.globalServices,
		storeFactory:       cm.storeFactory,
		synced:             newSynced(),
		status:             status,
		clusterAddHooks:    cm.clusterAddHooks,
		clusterDeleteHooks: cm.clusterDeleteHooks,
	}

	rc.remoteServices = cm.storeFactory.NewWatchStore(
		name,
		func() store.Key { return new(serviceStore.ClusterService) },
		&remoteServiceObserver{
			globalServices:            cm.globalServices,
			clusterServiceUpdateHooks: cm.clusterServiceUpdateHooks,
			clusterServiceDeleteHooks: cm.clusterServiceDeleteHooks,
		},
		store.RWSWithOnSyncCallback(func(ctx context.Context) { rc.synced.services.Stop() }),
	)

	return rc
}

func (cm *clusterMesh) Start(startCtx cell.HookContext) error {
	log.Info("Bootstrap clustermesh EndpointSlice controller")
	cm.started.Store(true)

	cm.endpointSliceInformerFactory.Start(cm.context.Done())
	if err := cm.meshServiceInformer.Start(cm.context); err != nil {
		return err
	}
	cm.endpointSliceInformerFactory.WaitForCacheSync(startCtx.Done())

	if !cache.WaitForCacheSync(startCtx.Done(), cm.meshServiceInformer.HasSynced) {
		return fmt.Errorf("waitForCacheSync on service informer not successful")
	}

	go func() {
		if err := cm.ServicesSynced(cm.context); err != nil &&
			!errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			log.Warnf("Error waiting for cluster mesh services to be synced: %s", err)
		}
		cm.endpointSliceMeshController.Run(cm.context, cm.concurrentClusterMeshEndpointSync)
	}()

	return nil
}

func (cm *clusterMesh) Stop(cell.HookContext) error {
	cm.contextCancel()
	return nil
}

// ServicesSynced returns after that the initial list of shared services has been
// received from all remote clusters.
func (cm *clusterMesh) ServicesSynced(ctx context.Context) error {
	return cm.synced(ctx, func(rc *remoteCluster) wait.Fn { return rc.synced.Services })
}

func (cm *clusterMesh) synced(ctx context.Context, toWaitFn func(*remoteCluster) wait.Fn) error {
	waiters := make([]wait.Fn, 0)
	cm.common.ForEachRemoteCluster(func(rci common.RemoteCluster) error {
		rc := rci.(*remoteCluster)
		waiters = append(waiters, toWaitFn(rc))
		return nil
	})

	return wait.ForAll(ctx, waiters)
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
