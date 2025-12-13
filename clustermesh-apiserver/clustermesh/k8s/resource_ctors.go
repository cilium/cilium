// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
)

var (
	PodPrefixLbl = labels.LabelSourceK8s + ":" + k8sConst.PodNamespaceLabel
)

func CiliumSlimEndpointResource(params k8s.CiliumResourceParams, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*types.CiliumEndpoint], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumEndpointList](params.ClientSet.CiliumV2().CiliumEndpoints(slim_corev1.NamespaceAll)),
		opts...,
	)
	return resource.New[*types.CiliumEndpoint](params.Lifecycle, lw, mp,
		resource.WithLazyTransform(func() runtime.Object {
			return &cilium_api_v2.CiliumEndpoint{}
		}, k8s.TransformToCiliumEndpoint),
		resource.WithCRDSync(params.CRDSyncPromise),
		resource.WithIndexers(
			cache.Indexers{
				cache.NamespaceIndex: cache.MetaNamespaceIndexFunc, // index by namespace for global namespace lookups
			},
		),
	), nil
}

func CiliumNodeResource(params k8s.CiliumResourceParams, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNode], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](params.ClientSet.CiliumV2().CiliumNodes()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumNode](params.Lifecycle, lw, mp,
		resource.WithMetric("CiliumNode"), resource.WithCRDSync(params.CRDSyncPromise),
	), nil
}

func CiliumEndpointSliceResource(params k8s.CiliumResourceParams, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumEndpointSlice], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumEndpointSliceList](params.ClientSet.CiliumV2alpha1().CiliumEndpointSlices()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumEndpointSlice](params.Lifecycle, lw, mp,
		resource.WithMetric("CiliumEndpointSlice"), resource.WithCRDSync(params.CRDSyncPromise),
		resource.WithIndexers(
			cache.Indexers{
				cache.NamespaceIndex: ciliumEndpointSliceNamespaceIndexFunc, // index by namespace for global namespace lookups
			},
		),
	), nil
}

func CiliumIdentityResource(params k8s.CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumIdentity], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumIdentityList](params.ClientSet.CiliumV2().CiliumIdentities()),
		opts...,
	)

	return resource.New[*cilium_api_v2.CiliumIdentity](params.Lifecycle, lw,
		params.MetricsProvider, resource.WithMetric("CiliumIdentityList"),
		resource.WithIndexers(
			cache.Indexers{
				cache.NamespaceIndex: ciliumIdentityNamespaceIndexFunc, // index by namespace for global namespace lookups
			},
		),
		resource.WithCRDSync(params.CRDSyncPromise)), nil
}

// ciliumIdentityNamespaceIndexFunc extracts the namespace from CiliumIdentity SecurityLabels.
// Since CiliumIdentity is cluster-scoped, we extract namespace from security labels.
func ciliumIdentityNamespaceIndexFunc(obj any) ([]string, error) {
	switch t := obj.(type) {
	case *cilium_api_v2.CiliumIdentity:
		// Look for the namespace in security labels.
		if namespace, exists := t.SecurityLabels[PodPrefixLbl]; exists {
			return []string{namespace}, nil
		}
		// If no namespace found, return empty slice (no namespace association).
		return []string{}, nil
	}
	return nil, fmt.Errorf("object is not a *cilium_api_v2.CiliumIdentity - got %T", obj)
}

// ciliumEndpointSliceNamespaceIndexFunc extracts the namespace from CiliumEndpointSlice.
// Since CiliumEndpointSlice has a dedicated Namespace field, we use that directly.
func ciliumEndpointSliceNamespaceIndexFunc(obj any) ([]string, error) {
	switch t := obj.(type) {
	case *cilium_api_v2alpha1.CiliumEndpointSlice:
		if t.Namespace != "" {
			return []string{t.Namespace}, nil
		}
		return []string{}, nil
	}
	return nil, fmt.Errorf("object is not a *cilium_api_v2alpha1.CiliumEndpointSlice - got %T", obj)
}
