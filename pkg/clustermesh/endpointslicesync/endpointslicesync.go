// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	cache "k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// newNamespaceWatcher creates a namespace watcher for endpointslicesync if namespaces resource is available.
func newNamespaceWatcher(namespaces resource.Resource[*slim_corev1.Namespace]) clustermesh.GlobalNamespaceTracker {
	if namespaces == nil {
		return nil
	}
	watcher := clustermesh.NewNamespaceWatcherFromEnv()
	watcher.SetNamespaceResource(namespaces)
	return watcher
}

func registerEndpointSliceSync(_ cell.Lifecycle, params endpointSliceSyncParams) {
	if !params.Clientset.IsEnabled() || params.ClusterMesh == nil || !params.ClusterMeshEnableEndpointSync {
		return
	}

	params.Logger.Info("Endpoint Slice Cluster Mesh synchronization enabled")

	// Initialize namespace tracker for global service filtering
	namespaceWatcher := newNamespaceWatcher(params.Namespaces)

	meshPodInformer := newMeshPodInformer(params.Logger, params.ClusterMesh.GlobalServices())
	params.ClusterMesh.RegisterClusterServiceUpdateHook(meshPodInformer.onClusterServiceUpdate)
	params.ClusterMesh.RegisterClusterServiceDeleteHook(meshPodInformer.onClusterServiceDelete)
	meshNodeInformer := newMeshNodeInformer(params.Logger)
	params.ClusterMesh.RegisterClusterAddHook(meshNodeInformer.onClusterAdd)
	params.ClusterMesh.RegisterClusterDeleteHook(meshNodeInformer.onClusterDelete)
	params.JobGroup.Add(job.OneShot("endpointslicesync-main", func(ctx context.Context, health cell.Health) error {
		params.Logger.Info("Bootstrap clustermesh EndpointSlice controller")

		endpointSliceMeshController, meshServiceInformer, endpointSliceInformerFactory := newEndpointSliceMeshController(
			ctx, params.Logger, params.EndpointSliceSyncConfig, meshPodInformer,
			meshNodeInformer, params.Clientset,
			params.Services, params.ClusterMesh.GlobalServices(), namespaceWatcher,
		)

		endpointSliceInformerFactory.Start(ctx.Done())
		if err := meshServiceInformer.Start(ctx); err != nil {
			return err
		}
		endpointSliceInformerFactory.WaitForCacheSync(ctx.Done())

		if !cache.WaitForCacheSync(ctx.Done(), meshServiceInformer.HasSynced) {
			return fmt.Errorf("waitForCacheSync on service informer not successful")
		}

		if err := params.ClusterMesh.ServicesSynced(ctx); err != nil {
			return nil // The parent context expired, and we are already terminating
		}
		endpointSliceMeshController.Run(ctx, params.ClusterMeshConcurrentEndpointSync)
		return nil
	}))
}
