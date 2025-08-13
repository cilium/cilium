// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

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
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	return resource.New[*types.CiliumEndpoint](params.Lifecycle, lw,
		resource.WithLazyTransform(func() runtime.Object {
			return &cilium_api_v2.CiliumEndpoint{}
		}, k8s.TransformToCiliumEndpoint), 
		resource.WithCRDSync(params.CRDSyncPromise),
		resource.WithIndexers(indexers),
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
	indexers := cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	}
	return resource.New[*cilium_api_v2alpha1.CiliumEndpointSlice](params.Lifecycle, lw,
		resource.WithMetric("CiliumEndpointSlice"), 
		resource.WithCRDSync(params.CRDSyncPromise),
		resource.WithIndexers(indexers),
	), nil
}

// CiliumIdentityNamespaceIndexFunc extracts the namespace from CiliumIdentity SecurityLabels.
// Since CiliumIdentity is cluster-scoped, we extract namespace from security labels.
func CiliumIdentityNamespaceIndexFunc(obj any) ([]string, error) {
	switch t := obj.(type) {
	case *cilium_api_v2.CiliumIdentity:
		// Look for the namespace in security labels
		if namespace, exists := t.SecurityLabels["io.kubernetes.pod.namespace"]; exists {
			return []string{namespace}, nil
		}
		// If no namespace found, return empty slice (no namespace association)
		return []string{}, nil
	}
	return nil, fmt.Errorf("%w - found %T", errors.New("object is not a *cilium_api_v2.CiliumIdentity"), obj)
}

func CiliumIdentityResource(params k8s.CiliumResourceParams, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumIdentity], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumIdentityList](params.ClientSet.CiliumV2().CiliumIdentities()),
		opts...,
	)
	indexers := cache.Indexers{
		cache.NamespaceIndex: CiliumIdentityNamespaceIndexFunc,
	}
	return resource.New[*cilium_api_v2.CiliumIdentity](params.Lifecycle, lw,
		resource.WithMetric("CiliumIdentity"), 
		resource.WithCRDSync(params.CRDSyncPromise),
		resource.WithIndexers(indexers),
	), nil
}
