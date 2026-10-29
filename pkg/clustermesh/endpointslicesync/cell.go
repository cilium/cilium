// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	cmendpointslice "github.com/cilium/cilium/pkg/clustermesh/endpointslice"
	cmnamespace "github.com/cilium/cilium/pkg/clustermesh/namespace"
	"github.com/cilium/cilium/pkg/clustermesh/operator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	endpointslicetypes "github.com/cilium/cilium/pkg/clustermesh/types/endpointslice"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

const ServiceIndex = "service"

type enabledParams struct {
	cell.In

	Clientset k8sClient.Clientset
	operator.ClusterMeshConfig
	cmtypes.ServiceModeV2Config
}

func shouldBeEnabled(p enabledParams) bool {
	return p.Clientset.IsEnabled() &&
		p.ClusterMeshEnableEndpointSync && p.ServiceModeV2.ShouldWatchEndpointSlices()
}

var Cell = cell.Module(
	"clustermesh-endpointslicesync",
	"EndpointSlice ClusterMesh synchronization from ClusterEndpointSlices",

	operator.Enable(func(p enabledParams) bool {
		return shouldBeEnabled(p)
	}),

	cell.ProvidePrivate(func(paramsShouldBeEnabled enabledParams) *operator.CacheStore[*endpointslicetypes.ClusterEndpointSlice] {
		if !shouldBeEnabled(paramsShouldBeEnabled) {
			return nil
		}
		return operator.NewCacheStore[*endpointslicetypes.ClusterEndpointSlice](cache.Indexers{
			cache.NamespaceIndex: func(obj any) ([]string, error) {
				remoteEndpointSlice, ok := obj.(*endpointslicetypes.ClusterEndpointSlice)
				if !ok {
					return nil, fmt.Errorf("unexpected object type: %T", obj)
				}
				return []string{remoteEndpointSlice.Namespace}, nil
			},
			ServiceIndex: func(obj any) ([]string, error) {
				remoteEndpointSlice, ok := obj.(*endpointslicetypes.ClusterEndpointSlice)
				if !ok {
					return nil, fmt.Errorf("unexpected object type: %T", obj)
				}
				service := remoteEndpointSlice.Labels[discoveryv1.LabelServiceName]
				if service == "" {
					return nil, nil
				}
				return []string{types.NamespacedName{Name: service, Namespace: remoteEndpointSlice.Namespace}.String()}, nil
			},
		})
	}),
	cell.ProvidePrivate(func(paramsShouldBeEnabled enabledParams) *operator.RemoteObjectSource[*endpointslicetypes.ClusterEndpointSlice] {
		if !shouldBeEnabled(paramsShouldBeEnabled) {
			return nil
		}
		return operator.NewRemoteObjectSource(handler.TypedEnqueueRequestsFromMapFunc(
			func(_ context.Context, remoteEndpointSlice *endpointslicetypes.ClusterEndpointSlice) []ctrl.Request {
				return []ctrl.Request{{NamespacedName: remoteEndpointSliceReconcileKey(remoteEndpointSlice)}}
			},
		))
	}),
	cell.Provide(func(
		paramsShouldBeEnabled enabledParams,
		cache *operator.CacheStore[*endpointslicetypes.ClusterEndpointSlice],
		remoteEndpointSliceSource *operator.RemoteObjectSource[*endpointslicetypes.ClusterEndpointSlice],
	) cmendpointslice.Observer {
		if !shouldBeEnabled(paramsShouldBeEnabled) {
			return nil
		}
		return &store.FuncObserver[*endpointslicetypes.ValidatingClusterEndpointSlice]{
			OnUpdateFunc: func(remoteEndpointSlice *endpointslicetypes.ValidatingClusterEndpointSlice) {
				cache.Update(&remoteEndpointSlice.ClusterEndpointSlice)
				remoteEndpointSliceSource.OnEvent(&remoteEndpointSlice.ClusterEndpointSlice)
			},
			OnDeleteFunc: func(remoteEndpointSlice *endpointslicetypes.ValidatingClusterEndpointSlice) {
				cache.Delete(&remoteEndpointSlice.ClusterEndpointSlice)
				remoteEndpointSliceSource.OnEvent(&remoteEndpointSlice.ClusterEndpointSlice)
			},
		}
	}),
	cell.Invoke(registerEndpointSliceSync),
)

type params struct {
	cell.In

	Logger                    *slog.Logger
	JobGroup                  job.Group
	Manager                   ctrl.Manager
	ClusterMesh               operator.ClusterMesh
	NamespaceConfig           cmnamespace.Config
	Cache                     *operator.CacheStore[*endpointslicetypes.ClusterEndpointSlice]
	RemoteEndpointSliceSource *operator.RemoteObjectSource[*endpointslicetypes.ClusterEndpointSlice]
}

func registerEndpointSliceSync(paramsShouldBeEnabled enabledParams, p params) {
	if !shouldBeEnabled(paramsShouldBeEnabled) || p.ClusterMesh == nil {
		return
	}

	reconciler := &endpointSliceReconciler{
		Client: p.Manager.GetClient(), logger: p.Logger,
		cache: p.Cache, remoteEndpointSliceSource: p.RemoteEndpointSliceSource,
		namespaceConfig: p.NamespaceConfig,
	}
	p.JobGroup.Add(job.OneShot("endpointslicesync-reconciler", func(ctx context.Context, health cell.Health) error {
		if err := p.ClusterMesh.ObserverSynced(ctx, cmendpointslice.Name); err != nil {
			return nil // The parent context expired, and we are already terminating
		}
		if err := reconciler.SetupWithManager(p.Manager); err != nil {
			return fmt.Errorf("failed to register ClusterEndpointSlice sync controller: %w", err)
		}
		return nil
	}))
}
