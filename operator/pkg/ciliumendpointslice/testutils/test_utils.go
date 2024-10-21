// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package testutils

import (
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func CreateManagerEndpoint(name string, identity int64) capi_v2a1.CoreCiliumEndpoint {
	return capi_v2a1.CoreCiliumEndpoint{
		Name:       name,
		IdentityID: identity,
	}
}

func CreateStoreEndpointSlice(name string, namespace string, endpoints []capi_v2a1.CoreCiliumEndpoint) *capi_v2a1.CiliumEndpointSlice {
	return &capi_v2a1.CiliumEndpointSlice{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: name,
		},
		Namespace: namespace,
		Endpoints: endpoints,
	}
}

func CreateStorePod(name string, namespace string, identity int64) *slim_corev1.Pod {
	return &slim_corev1.Pod{
		TypeMeta: slim_metav1.TypeMeta{},
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec:   slim_corev1.PodSpec{},
		Status: slim_corev1.PodStatus{},
	}
}

func CreateCESWithIDs(cesName string, ids []int64) *capi_v2a1.CiliumEndpointSlice {
	ces := &capi_v2a1.CiliumEndpointSlice{ObjectMeta: meta_v1.ObjectMeta{Name: cesName}}
	for _, id := range ids {
		cep := capi_v2a1.CoreCiliumEndpoint{IdentityID: id}
		ces.Endpoints = append(ces.Endpoints, cep)
	}
	return ces
}
