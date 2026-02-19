// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"context"
	"log/slog"
	"time"

	"github.com/cilium/endpointslice-controller/endpointslice"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	discoveryv1 "k8s.io/client-go/kubernetes/typed/discovery/v1"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

// endpointSliceCleanupFactory returns a function used as a hook when no service are found in
// EndpointSlice controller. Usually EndpointSlice get cleaned up via OwnerReference whenever
// the service is deleted, but for the clustermesh case the Service could still
// exist but should no longer sync the remote cluster EndpintSlice, so we need to make
// sure the existing EndpointSlice from remote clusters are properly deleted.
func endpointSliceCleanupFactory(ctx context.Context, discoveryClient discoveryv1.DiscoveryV1Interface) func(namespace, name string) error {
	return func(namespace, name string) error {
		labelSelector := metav1.FormatLabelSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{
				discovery.LabelManagedBy: utils.EndpointSliceMeshControllerName,
			},
		})
		// Note that we have to query the EndpointSlices directly with the client
		// instead of through the informer cache. The informer cache is asynchronously
		// updated so even if we are the sole write/owner of those object relying
		// on the informer cache may result in race conditions.
		endpointSlices, err := discoveryClient.EndpointSlices(namespace).
			List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
		if err != nil {
			return err
		}
		for _, endpointSlice := range endpointSlices.Items {
			// Note that this label checks is necessarily client side because
			// that labels is virtually added through the meshClient
			// and cannot be queried directly on the the API server.
			if endpointSlice.Labels[discovery.LabelServiceName] != name {
				continue
			}
			deleteOpt := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{
				UID: &endpointSlice.UID,
			}}
			if err = discoveryClient.EndpointSlices(endpointSlice.Namespace).
				Delete(ctx, endpointSlice.Name, deleteOpt); err != nil && !errors.IsNotFound(err) {
				return err
			}
		}

		return nil
	}
}

func newEndpointSliceMeshController(
	ctx context.Context, logger *slog.Logger, cfg EndpointSliceSyncConfig,
	meshPodInformer *meshPodInformer, meshNodeInformer *meshNodeInformer,
	clientset k8sClient.Clientset, services resource.Resource[*slim_corev1.Service],
	globalServices *common.GlobalServiceCache,
) (*endpointslice.Controller, *meshServiceInformer, informers.SharedInformerFactory) {
	meshClient := meshClient{clientset}

	factory := informers.NewSharedInformerFactory(meshClient, 12*time.Hour)
	endpointSliceInformer := factory.Discovery().V1().EndpointSlices()

	meshServiceInformer := newMeshServiceInformer(
		logger, globalServices, services, meshNodeInformer,
	)

	controller := endpointslice.NewControllerWithName(
		ctx, meshPodInformer, meshServiceInformer,
		meshNodeInformer, endpointSliceInformer,
		int32(cfg.ClusterMeshMaxEndpointsPerSlice),
		meshClient, cfg.ClusterMeshEndpointUpdatesBatchPeriod,
		utils.EndpointSliceMeshControllerName, nil,
		endpointSliceCleanupFactory(ctx, meshClient.DiscoveryV1()),
	)

	return controller, meshServiceInformer, factory
}
