// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This package contains exported resource identifiers and metric resource labels related to
// K8s watchers.
package resources

import (
	"k8s.io/apimachinery/pkg/api/meta"

	"github.com/cilium/cilium/pkg/container/cache"
)

const (
	// K8sAPIGroupNetworkingV1Core is the identifier for K8S resources of type networking.k8s.io/v1/NetworkPolicy
	K8sAPIGroupNetworkingV1Core = "networking.k8s.io/v1::NetworkPolicy"
	// K8sAPIGroupNamespaceV1Core is the identifier for K8s resources of type core/v1/Namespace.
	K8sAPIGroupNamespaceV1Core = "core/v1::Namespace"
	// K8sAPIGroupServiceV1Core is the identifier for K8s resources of type core/v1/Service.
	K8sAPIGroupServiceV1Core = "core/v1::Service"
	// K8sAPIGroupPodV1Core is the identifier for K8s resources of type core/v1/Pod.
	K8sAPIGroupPodV1Core = "core/v1::Pods"
	// K8sAPIGroupEndpointSliceOrEndpoint is the combined identifier for K8s EndpointSlice and
	// Endpoint resources.
	K8sAPIGroupEndpointSliceOrEndpoint = "EndpointSliceOrEndpoint"

	// MetricCNP is the scope label for CiliumNetworkPolicy event metrics.
	MetricCNP = "CiliumNetworkPolicy"
	// MetricCCNP is the scope label for CiliumClusterwideNetworkPolicy event metrics.
	MetricCCNP = "CiliumClusterwideNetworkPolicy"
	// MetricCCG is the scope label for CiliumCIDRGroup event metrics.
	MetricCCG = "CiliumCIDRGroup"
	// MetricService is the scope label for Kubernetes Service event metrics.
	MetricService = "Service"
	// MetricEndpoint is the scope label for Kubernetes Endpoint event metrics.
	MetricEndpoint = "Endpoint"
	// MetricEndpointSlice is the scope label for Kubernetes EndpointSlice event metrics.
	MetricEndpointSlice = "EndpointSlice"

	// MetricCreate the label for watcher metrics related to create events.
	MetricCreate = "create"
	// MetricUpdate the label for watcher metrics related to update events.
	MetricUpdate = "update"
	// MetricDelete the label for watcher metrics related to delete events.
	MetricDelete = "delete"
)

// dedupMetadata deduplicates the allocated strings in the metadata using the container/cache package.
func DedupMetadata(obj any) {
	meta, err := meta.Accessor(obj)
	if err != nil {
		return
	}
	meta.SetName(cache.Strings.Get(meta.GetName()))
	meta.SetNamespace(cache.Strings.Get(meta.GetNamespace()))
	meta.SetLabels(cache.StringMaps.Get(meta.GetLabels()))
	meta.SetAnnotations(cache.StringMaps.Get(meta.GetAnnotations()))
}
