// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This package contains exported resource identifiers and metric resource labels related to
// K8s watchers.
package resources

const (
	// K8sAPIGroupServiceV1Core is the identifier for K8s resources of type core/v1/Service.
	K8sAPIGroupServiceV1Core = "core/v1::Service"
	// K8sAPIGroupEndpointV1Core is the identifier for K8s resources of type core/v1/Endpoint.
	K8sAPIGroupEndpointV1Core = "core/v1::Endpoint"
	// K8sAPIGroupPodV1Core is the identifier for K8s resources of type core/v1/Pod.
	K8sAPIGroupPodV1Core = "core/v1::Pods"
	// K8sAPIGroupSecretV1Cores is the identifier for K8s resources of type core/v1/Secret.
	K8sAPIGroupSecretV1Core = "core/v1::Secrets"
	// K8sAPIGroupEndpointSliceV1Beta1Discovery is the identifier for K8s resources of type discovery/v1beta1/EndpointSlice.
	K8sAPIGroupEndpointSliceV1Beta1Discovery = "discovery/v1beta1::EndpointSlice"
	// K8sAPIGroupEndpointSliceV1Beta1Discovery is the identifier for K8s resources of type discovery/v1/EndpointSlice.
	// todo(tom): double check the uses of these two.
	K8sAPIGroupEndpointSliceV1Discovery = "discovery/v1::EndpointSlice"

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
