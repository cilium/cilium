// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

func CiliumSlimEndpointResource(params k8s.CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*types.CiliumEndpoint], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumEndpointList](params.ClientSet.CiliumV2().CiliumEndpoints(slim_corev1.NamespaceAll)),
		opts...,
	)
	return resource.New[*types.CiliumEndpoint](params.Lifecycle, lw,
		resource.WithLazyTransform(func() runtime.Object {
			return &cilium_api_v2.CiliumEndpoint{}
		}, k8s.TransformToCiliumEndpoint), resource.WithCRDSync(params.CRDSyncPromise),
	), nil
}

func CiliumNodeResource(params k8s.CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNode], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](params.ClientSet.CiliumV2().CiliumNodes()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumNode](params.Lifecycle, lw,
		resource.WithMetric("CiliumNode"), resource.WithCRDSync(params.CRDSyncPromise),
	), nil
}

func CiliumEndpointSliceResource(params k8s.CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumEndpointSlice], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumEndpointSliceList](params.ClientSet.CiliumV2alpha1().CiliumEndpointSlices()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumEndpointSlice](params.Lifecycle, lw,
		resource.WithMetric("CiliumEndpointSlice"), resource.WithCRDSync(params.CRDSyncPromise),
	), nil
}
