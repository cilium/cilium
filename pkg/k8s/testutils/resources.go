// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	corev1 "k8s.io/api/core/v1"
	discov1 "k8s.io/api/discovery/v1"
	discov1beta1 "k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var (
	DefaultVersion = "1.26"

	// APIResources is the list of API resources for the k8s version that we're mocking.
	// This is mostly relevant for the feature detection at pkg/k8s/version/version.go.
	// The lists here are currently not exhaustive and expanded on need-by-need basis.
	APIResources = map[string][]*metav1.APIResourceList{
		"1.16": {
			CoreV1APIResources,
			CiliumV2APIResources,
		},
		"1.24": {
			CoreV1APIResources,
			DiscoveryV1APIResources,
			DiscoveryV1Beta1APIResources,
			CiliumV2APIResources,
		},
		"1.25": {
			CoreV1APIResources,
			DiscoveryV1APIResources,
			CiliumV2APIResources,
		},
		"1.26": {
			CoreV1APIResources,
			DiscoveryV1APIResources,
			CiliumV2APIResources,
		},
	}

	CoreV1APIResources = &metav1.APIResourceList{
		GroupVersion: corev1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "nodes", Kind: "Node"},
			{Name: "pods", Namespaced: true, Kind: "Pod"},
			{Name: "services", Namespaced: true, Kind: "Service"},
			{Name: "endpoints", Namespaced: true, Kind: "Endpoint"},
		},
	}

	CiliumV2APIResources = &metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{},
		GroupVersion: cilium_v2.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: cilium_v2.CNPluralName, Kind: cilium_v2.CNKindDefinition},
			{Name: cilium_v2.CEPPluralName, Namespaced: true, Kind: cilium_v2.CEPKindDefinition},
			{Name: cilium_v2.CIDPluralName, Namespaced: true, Kind: cilium_v2.CIDKindDefinition},
			{Name: cilium_v2.CEGPPluralName, Namespaced: true, Kind: cilium_v2.CEGPKindDefinition},
			{Name: cilium_v2.CNPPluralName, Namespaced: true, Kind: cilium_v2.CNPKindDefinition},
			{Name: cilium_v2.CCNPPluralName, Namespaced: true, Kind: cilium_v2.CCNPKindDefinition},
			{Name: cilium_v2.CLRPPluralName, Namespaced: true, Kind: cilium_v2.CLRPKindDefinition},
			{Name: cilium_v2.CCECPluralName, Namespaced: true, Kind: cilium_v2.CCECKindDefinition},
			{Name: cilium_v2.CECPluralName, Namespaced: true, Kind: cilium_v2.CECKindDefinition},
		},
	}

	DiscoveryV1APIResources = &metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{},
		GroupVersion: discov1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "endpointslices", Namespaced: true, Kind: "EndpointSlice"},
		},
	}

	DiscoveryV1Beta1APIResources = &metav1.APIResourceList{
		GroupVersion: discov1beta1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "endpointslices", Namespaced: true, Kind: "EndpointSlice"},
		},
	}
)
