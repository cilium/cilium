// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/endpointslice-controller/endpointslice"
	"k8s.io/client-go/informers"
	cache "k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/hive/cell"
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
}

func newClusterMesh(lc cell.Lifecycle, params clusterMeshParams) *clusterMesh {
	if !params.Clientset.IsEnabled() || params.ClusterMeshConfig == "" {
		return nil
	}

	log.WithField("enabled", params.Cfg.ClusterMeshEnableEndpointSync).
		Info("Endpoint Slice Cluster Mesh synchronization")

	if !params.Cfg.ClusterMeshEnableEndpointSync {
		return nil
	}

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
	cm.meshNodeInformer = newMeshNodeInformer()
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
	return &cm
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

func (cm *clusterMesh) newRemoteCluster(name string, status common.StatusFunc) common.RemoteCluster {
	rc := &remoteCluster{
		name:             name,
		meshNodeInformer: cm.meshNodeInformer,
		globalServices:   cm.globalServices,
		storeFactory:     cm.storeFactory,
		synced:           newSynced(),
	}

	rc.remoteServices = cm.storeFactory.NewWatchStore(
		name,
		func() store.Key { return new(serviceStore.ClusterService) },
		&remoteServiceObserver{globalServices: cm.globalServices, meshPodInformer: cm.meshPodInformer},
		store.RWSWithOnSyncCallback(func(ctx context.Context) { rc.synced.services.Stop() }),
	)

	return rc
}

func (cm *clusterMesh) Start(startCtx cell.HookContext) error {
	log.Info("Bootstrap clustermesh EndpointSlice controller")

	cm.endpointSliceInformerFactory.Start(cm.context.Done())
	if err := cm.meshServiceInformer.Start(cm.context); err != nil {
		return err
	}
	cm.endpointSliceInformerFactory.WaitForCacheSync(startCtx.Done())

	if !cache.WaitForCacheSync(startCtx.Done(), cm.meshServiceInformer.HasSynced) {
		return fmt.Errorf("waitForCacheSync on service informer not successful")
	}

	go func() {
		// Wait for clustermesh services to be synced
		cm.ServicesSynced(cm.context)

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
